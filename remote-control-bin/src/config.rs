#![allow(dead_code)]
use crate::error::{Error, ErrorKind};
use crate::template::{Template, TemplateContext};
use bytes::{Bytes, BytesMut};
use remote_control_protocol::config::Logger as LoggerTrait;
use remote_control_protocol::config::{LogFormat, LogLevel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex, RwLock};

#[macro_export]
macro_rules! trace {
    ($logger:expr, $($args : tt) *) => {
        {
            use remote_control_protocol::config::{Logger, LogLevel};
            if $logger.level() >= LogLevel::Trace {
                $logger.trace(&format!($($args)*));
            }
        }
    }
}

#[macro_export]
macro_rules! error {
    ($logger:expr, $($args : tt) *) => {
        {
            use remote_control_protocol::config::{Logger, LogLevel};
            if $logger.level() >= LogLevel::Error {
                $logger.error(&format!($($args)*));
            }
        }
    }
}

struct ConfigData {
    detach: bool,
    runtime_dir: PathBuf,
    format: LogFormat,
    config_file: ConfigFile,
    root: Option<bool>,
}

pub struct Config {
    logger: Arc<Logger>,
    data: RwLock<ConfigData>,
    env_vars: BTreeMap<Bytes, Bytes>,
}

impl Config {
    pub fn new<
        E: FnMut(&str) -> Option<OsString>,
        I: Iterator<Item = (OsString, OsString)>,
        V: FnMut() -> I,
    >(
        env: E,
        env_iter: V,
        create: bool,
        verbosity: i32,
        stdout: Box<dyn Write + Sync + Send>,
        stderr: Box<dyn Write + Sync + Send>,
        config_file: Option<&PathBuf>,
    ) -> Result<Config, Error> {
        let mut env_iter = env_iter;
        let logger = Logger::new(verbosity, stdout, stderr);
        let runtime_dir = Self::create_runtime_dir(&logger, env, create).ok_or_else(|| {
            Error::new_with_message(
                ErrorKind::RuntimeDirectoryFailure,
                "cannot detect runtime directory",
            )
        })?;
        let config_file = {
            match config_file {
                Some(name) => match fs::File::open(name) {
                    Ok(f) => match serde_yaml::from_reader(f) {
                        Ok(config) => config,
                        Err(e) => {
                            return Err(Error::new_with_cause(ErrorKind::InvalidConfigFile, e))
                        }
                    },
                    Err(e) => return Err(Error::new_with_cause(ErrorKind::MissingConfigFile, e)),
                },
                None => ConfigFile::new(),
            }
        };
        Ok(Self {
            logger: Arc::new(logger),
            data: RwLock::new(ConfigData {
                detach: true,
                runtime_dir,
                format: LogFormat::Text,
                config_file,
                root: None,
            }),
            env_vars: env_iter()
                .map(|(k, v)| (k.as_bytes().to_vec().into(), v.as_bytes().to_vec().into()))
                .collect(),
        })
    }

    pub fn template_context<'a>(
        &self,
        cenv: Option<&'a BTreeMap<Bytes, Bytes>>,
        args: Option<&'a [Bytes]>,
    ) -> TemplateContext<'_, 'a> {
        TemplateContext {
            senv: Some(&self.env_vars),
            cenv,
            args,
        }
    }

    pub fn format(&self) -> LogFormat {
        let g = self.data.read().unwrap();
        g.format
    }

    pub fn set_format(&self, format: LogFormat) {
        {
            let mut g = self.data.write().unwrap();
            g.format = format;
        }
        self.logger.set_format(format);
    }

    pub fn set_detach(&self, detach: bool) {
        let mut g = self.data.write().unwrap();
        g.detach = detach;
    }

    pub fn logger(&self) -> Arc<Logger> {
        self.logger.clone()
    }

    pub fn detach(&self) -> bool {
        let g = self.data.read().unwrap();
        g.detach
    }

    pub fn runtime_dir(&self) -> PathBuf {
        let g = self.data.read().unwrap();
        g.runtime_dir.clone()
    }

    pub fn is_root(&self) -> Result<bool, Error> {
        let val = {
            let g = self.data.read().unwrap();
            if let Some(val) = g.root {
                return Ok(val);
            }
            // This is the default algorithm for determining whether we're running in a GUI.  It is
            // subject to change at any time.
            g.config_file.v0.root.clone().unwrap_or_else(|| "![ -z \"$SSH_TTY\" ] && { [ -n \"$WAYLAND_DISPLAY\" ] || [ -n \"$DISPLAY\" ] || [ \"$(uname -s)\" = Darwin ]; }".to_string())
        };
        let ctx = self.template_context(None, None);
        let result = ConfigValue::new(&val, &ctx)?.into_bool();
        let mut g = self.data.write().unwrap();
        g.root = Some(result);
        Ok(result)
    }

    pub fn config_command(&self, name: &[u8]) -> Option<ConfigCommand> {
        let name = match String::from_utf8(name.to_vec()) {
            Ok(name) => name,
            Err(_) => return None,
        };
        let g = self.data.read().unwrap();
        let commands = g.config_file.v0.commands.as_ref()?;
        Some(commands.get(&name)?.clone())
    }

    pub fn sockets(&self) -> Vec<PathBuf> {
        let logger = self.logger.clone();
        Self::find_sockets(&logger, |s| {
            self.env_vars
                .get(&Bytes::copy_from_slice(s.as_bytes()))
                .map(|x| OsStr::from_bytes(x).into())
        })
    }

    fn find_runtime_dirs<E: FnMut(&str) -> Option<OsString>>(
        logger: &Logger,
        mut env: E,
    ) -> Vec<PathBuf> {
        let mut v = vec![];
        logger.trace("runtime_dir: looking for XDG_RUNTIME_DIR");
        if let Some(dir) = env("XDG_RUNTIME_DIR") {
            let mut buf: PathBuf = dir.into();
            buf.push("remote-control");
            logger.trace(&format!("runtime_dir: found, using {:?}", buf));
            v.push(buf);
        }
        let uid = unsafe { libc::getuid() };
        let path = format!("/run/user/{}", uid);
        logger.trace(&format!("runtime_dir: looking for {}", path));
        if fs::metadata(&path).is_ok() {
            let mut buf: PathBuf = path.into();
            buf.push("remote-control");
            logger.trace(&format!("runtime_dir: found, using {:?}", buf));
            v.push(buf);
        }
        logger.trace("runtime_dir: looking for HOME");
        if let Some(dir) = env("HOME") {
            let mut buf: PathBuf = dir.into();
            buf.push(".local");
            buf.push("remote-control");
            buf.push("runtime");
            logger.trace(&format!("runtime_dir: found, using {:?}", buf));
            v.push(buf);
        }
        v
    }

    fn find_sockets<E: FnMut(&str) -> Option<OsString>>(logger: &Logger, env: E) -> Vec<PathBuf> {
        let dirs = Self::find_runtime_dirs(logger, env);
        let mut v = vec![];
        for dir in dirs {
            if let Ok(iter) = std::fs::read_dir(&dir) {
                v.extend(iter.filter_map(|f| {
                    let f = match f {
                        Ok(f) => f,
                        Err(_) => return None,
                    };
                    match f.file_type() {
                        Ok(m) if m.is_socket() => Some(f.path()),
                        _ => None,
                    }
                }));
            }
        }
        v
    }

    fn find_runtime_dir<E: FnMut(&str) -> Option<OsString>>(
        logger: &Logger,
        env: E,
    ) -> Option<PathBuf> {
        match Self::find_runtime_dirs(logger, env).get(0) {
            Some(s) => Some(s.clone()),
            None => {
                trace!(logger, "runtime_dir: unable to find runtime directory");
                None
            }
        }
    }

    fn create_runtime_dir<E: FnMut(&str) -> Option<OsString>>(
        logger: &Logger,
        env: E,
        create: bool,
    ) -> Option<PathBuf> {
        let dir = Self::find_runtime_dir(logger, env)?;
        if create {
            logger.trace("runtime_dir: attempting to create");
            match std::fs::create_dir_all(&dir) {
                Ok(()) => {
                    logger.trace("runtime_dir: successfully created");
                    return Some(dir);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    logger.trace("runtime_dir: already exists (success)");
                    return Some(dir);
                }
                Err(e) => {
                    logger.trace(&format!("runtime_dir: failed: {}", e));
                    return None;
                }
            }
        }
        Some(dir)
    }
}

pub struct Logger {
    output: Mutex<Box<dyn Write + Sync + Send>>,
    error: Mutex<Box<dyn Write + Sync + Send>>,
    verbosity: i32,
    level: LogLevel,
    format: RwLock<LogFormat>,
}

impl Logger {
    pub fn new(
        verbosity: i32,
        output: Box<dyn Write + Sync + Send>,
        error: Box<dyn Write + Sync + Send>,
    ) -> Self {
        let level = match verbosity {
            x if x < -1 => LogLevel::Fatal,
            -1 => LogLevel::Error,
            0 => LogLevel::Normal,
            1 => LogLevel::Info,
            2 => LogLevel::Debug,
            3 => LogLevel::Trace,
            _ => LogLevel::Trace,
        };
        Self {
            output: Mutex::new(output),
            error: Mutex::new(error),
            verbosity,
            level,
            format: RwLock::new(LogFormat::Text),
        }
    }

    fn write(&self, desired: i32, io: &Mutex<Box<dyn Write + Sync + Send>>, msg: &str) {
        if self.verbosity >= desired {
            let mut m = io.lock().unwrap();
            let _ = m.write_all(msg.as_bytes());
        }
    }

    fn set_format(&self, format: LogFormat) {
        let mut g = self.format.write().unwrap();
        *g = format;
    }
}

impl remote_control_protocol::config::Logger for Logger {
    fn level(&self) -> LogLevel {
        self.level
    }

    fn format(&self) -> LogFormat {
        let g = self.format.read().unwrap();
        *g
    }

    fn fatal(&self, msg: &str) {
        self.write(-1, &self.error, &format!("fatal: {}\n", msg));
    }

    fn error(&self, msg: &str) {
        self.write(-1, &self.error, &format!("error: {}\n", msg));
    }

    fn message(&self, msg: &str) {
        let format = {
            let g = self.format.read().unwrap();
            *g
        };
        if format == LogFormat::Text {
            self.write(0, &self.output, &format!("{}\n", msg));
        }
    }

    fn info(&self, msg: &str) {
        self.write(1, &self.error, &format!("info: {}\n", msg));
    }

    fn debug(&self, msg: &str) {
        self.write(2, &self.error, &format!("debug: {}\n", msg));
    }

    fn trace(&self, msg: &str) {
        self.write(3, &self.error, &format!("trace: {}\n", msg));
    }
}

pub struct ConfigValue<'a, 'b, 'c> {
    command: Bytes,
    context: &'c TemplateContext<'a, 'b>,
}

impl<'a, 'b, 'c> ConfigValue<'a, 'b, 'c> {
    pub fn new(
        command: &str,
        context: &'c TemplateContext<'a, 'b>,
    ) -> Result<ConfigValue<'a, 'b, 'c>, Error> {
        Ok(ConfigValue {
            command: Self::templatize(command, context)?,
            context,
        })
    }

    fn templatize(s: &str, context: &'c TemplateContext<'a, 'b>) -> Result<Bytes, Error> {
        if s.is_empty() || !s.starts_with('!') {
            return Err(Error::new_with_message(
                ErrorKind::UnknownCommandType,
                format!("command {} must start with a !", s),
            ));
        }
        let t = Template::new(s[1..].as_bytes());
        t.expand(context).map_err(|e| {
            Error::new_full(
                ErrorKind::TemplateError,
                e,
                format!("invalid template string '{}'", s),
            )
        })
    }

    fn into_bool(self) -> bool {
        let mut cmd = self.create_command(&self.command);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(_) => return false,
        };
        match child.wait() {
            Ok(es) => es.success(),
            Err(_) => false,
        }
    }

    fn create_command(&self, shell: &Bytes) -> std::process::Command {
        let mut shell: BytesMut = shell.as_ref().into();
        if self.context.args.is_some() {
            shell.extend_from_slice(b" \"$@\"");
        }
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c");
        cmd.arg(OsStr::from_bytes(&shell));
        if let Some(args) = self.context.args {
            for arg in args {
                cmd.arg(OsString::from_vec(arg.to_vec()));
            }
        }
        if let Some(senv) = self.context.senv {
            cmd.env_clear();
            cmd.envs(senv.iter().map(|(k, v)| {
                (
                    OsString::from_vec(k.to_vec()),
                    OsString::from_vec(v.to_vec()),
                )
            }));
        }
        cmd.current_dir("/");
        cmd
    }
}

pub struct Command<'a, 'b, 'c> {
    condition: Option<Bytes>,
    pre: Vec<Bytes>,
    post: Vec<Bytes>,
    command: Bytes,
    context: &'c TemplateContext<'a, 'b>,
}

impl<'a, 'b, 'c> Command<'a, 'b, 'c> {
    pub fn new(
        config: &ConfigCommand,
        context: &'c TemplateContext<'a, 'b>,
    ) -> Result<Command<'a, 'b, 'c>, Error> {
        let pre = match &config.pre {
            Some(cmds) => cmds
                .iter()
                .map(|s| Self::templatize(s, context))
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };
        let post = match &config.post {
            Some(cmds) => cmds
                .iter()
                .map(|s| Self::templatize(s, context))
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };
        Ok(Command {
            condition: Some(Self::templatize(&config.if_value, context)?),
            pre,
            post,
            command: Self::templatize(&config.command, context)?,
            context,
        })
    }

    fn templatize(s: &str, context: &'c TemplateContext<'a, 'b>) -> Result<Bytes, Error> {
        if s.is_empty() || !s.starts_with('!') {
            return Err(Error::new_with_message(
                ErrorKind::UnknownCommandType,
                format!("command {} must start with a !", s),
            ));
        }
        let t = Template::new(s[1..].as_bytes());
        t.expand(context).map_err(|e| {
            Error::new_full(
                ErrorKind::TemplateError,
                e,
                format!("invalid template string '{}'", s),
            )
        })
    }

    fn create_command(&self, shell: &Bytes) -> tokio::process::Command {
        let mut shell: BytesMut = shell.as_ref().into();
        shell.extend_from_slice(b" \"$@\"");
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c");
        cmd.arg(OsStr::from_bytes(&shell));
        if let Some(args) = self.context.args {
            for arg in args {
                cmd.arg(OsString::from_vec(arg.to_vec()));
            }
        }
        if let Some(senv) = self.context.senv {
            cmd.env_clear();
            cmd.envs(senv.iter().map(|(k, v)| {
                (
                    OsString::from_vec(k.to_vec()),
                    OsString::from_vec(v.to_vec()),
                )
            }));
        }
        cmd.current_dir("/");
        cmd
    }

    async fn run_one(&self, shell: &Bytes) -> Result<i32, Error> {
        if shell == b"true" as &[u8] {
            return Ok(0);
        } else if shell == b"false" as &[u8] {
            return Ok(1);
        }
        let mut cmd = self.create_command(shell);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
        match cmd.spawn() {
            Ok(mut child) => match child.wait().await {
                Ok(status) => Ok(status
                    .code()
                    .or_else(|| status.signal().map(|x| x + 128))
                    .unwrap_or(-1)),
                // It's unclear in what situation this can happen.  The command ran, just not
                // successfully in our opinion.
                Err(_) => Ok(-1),
            },
            Err(e) => Err(Error::new_with_cause(ErrorKind::CommandFailure, e)),
        }
    }

    pub fn run_command(&self) -> tokio::process::Command {
        self.create_command(&self.command)
    }

    pub async fn check_condition(&self) -> Result<bool, Error> {
        match &self.condition {
            Some(cmd) => Ok(self.run_one(cmd).await? == 0),
            None => Ok(false),
        }
    }

    pub async fn run_pre_hooks(&self) -> Result<bool, Error> {
        let mut state = true;
        for hook in &self.pre {
            state = state && self.run_one(hook).await? == 0;
        }
        Ok(state)
    }

    pub async fn run_post_hooks(&self) -> Result<(), Error> {
        for hook in &self.post {
            self.run_one(hook).await?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct ConfigFile {
    v0: ConfigFileV0,
}

impl ConfigFile {
    fn new() -> Self {
        ConfigFile {
            v0: ConfigFileV0 {
                root: None,
                commands: None,
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ConfigFileV0 {
    root: Option<String>,
    commands: Option<BTreeMap<String, ConfigCommand>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigCommand {
    #[serde(rename = "if")]
    if_value: String,
    command: String,
    #[serde(rename = "pre")]
    pre: Option<Vec<String>>,
    #[serde(rename = "post")]
    post: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::{Config, ConfigFile};
    use std::collections::BTreeMap;
    use std::ffi::OsString;

    fn config_with_values<F: FnOnce(&mut ConfigFile)>(
        env: BTreeMap<OsString, OsString>,
        f: F,
    ) -> Config {
        let stdout = std::io::Cursor::new(Vec::new());
        let stderr = std::io::Cursor::new(Vec::new());
        let mut env = env;
        env.insert("PATH".into(), std::env::var_os("PATH").unwrap());
        let cfg = Config::new(
            |_| None,
            || env.iter().map(|(a, b)| (a.clone(), b.clone())),
            false,
            3,
            Box::new(stdout),
            Box::new(stderr),
            None,
        )
        .unwrap();
        {
            let mut g = cfg.data.write().unwrap();
            f(&mut g.config_file);
        }
        cfg
    }

    #[test]
    fn default_is_root() {
        let mut env = BTreeMap::new();
        env.insert("SSH_TTY".into(), "/nonexistent/pts/0".into());
        env.insert("DISPLAY".into(), ":none".into());
        let cfg = config_with_values(env, |_| ());
        assert_eq!(cfg.is_root().unwrap(), false);

        let mut env = BTreeMap::new();
        env.insert("DISPLAY".into(), ":none".into());
        let cfg = config_with_values(env, |_| ());
        assert_eq!(cfg.is_root().unwrap(), true);

        let mut env = BTreeMap::new();
        env.insert("WAYLAND_DISPLAY".into(), ":none".into());
        let cfg = config_with_values(env, |_| ());
        assert_eq!(cfg.is_root().unwrap(), true);
    }

    #[test]
    fn is_root_with_values() {
        let cfg = config_with_values(BTreeMap::new(), |c| c.v0.root = Some("!/bin/true".into()));
        assert_eq!(cfg.is_root().unwrap(), true);

        let cfg = config_with_values(BTreeMap::new(), |c| c.v0.root = Some("!/bin/false".into()));
        assert_eq!(cfg.is_root().unwrap(), false);

        let cfg = config_with_values(BTreeMap::new(), |c| {
            c.v0.root = Some("!cat /dev/null".into())
        });
        assert_eq!(cfg.is_root().unwrap(), true);
    }
}
