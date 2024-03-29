#![allow(dead_code)]
use crate::error::{Error, ErrorKind};
use crate::serializer::script::ScriptEncoder;
use crate::socket::LawnSocketData;
use crate::template::{Template, TemplateContext};
use bytes::{Bytes, BytesMut};
use format_bytes::format_bytes;
use lawn_constants::error::ExtendedError;
use lawn_constants::logger::Logger as LoggerTrait;
use lawn_constants::logger::{LogFormat, LogLevel};
use lawn_protocol::protocol::{
    Capability, ClipboardChannelOperation, ClipboardChannelTarget, Empty,
};
use rand::{CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::borrow::{Borrow, Cow};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::ops::Deref;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

pub const VERSION: &str = concat!("Lawn/", env!("CARGO_PKG_VERSION"));

#[allow(clippy::upper_case_acronyms)]
pub trait RNG: CryptoRng + RngCore + Send + Sync {}

impl<T> RNG for T
where
    T: CryptoRng,
    T: RngCore,
    T: Send,
    T: Sync,
{
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClipboardBackend {
    XClip,
    XSel,
    MacOS,
}

impl ClipboardBackend {
    pub fn supports_target(&self, target: ClipboardChannelTarget) -> bool {
        matches!(
            (self, target),
            (Self::XClip, _) | (Self::XSel, _) | (Self::MacOS, ClipboardChannelTarget::Clipboard)
        )
    }

    pub fn command(
        &self,
        target: ClipboardChannelTarget,
        op: ClipboardChannelOperation,
    ) -> Vec<Bytes> {
        let mut v: Vec<&'static [u8]> = Vec::new();
        match self {
            Self::XClip => {
                v.push(b"xclip");
                v.push(b"-selection");
                match target {
                    ClipboardChannelTarget::Primary => v.push(b"primary"),
                    ClipboardChannelTarget::Clipboard => v.push(b"clipboard"),
                }
                match op {
                    ClipboardChannelOperation::Copy => v.push(b"-i"),
                    ClipboardChannelOperation::Paste => v.push(b"-o"),
                }
            }
            Self::XSel => {
                v.push(b"xsel");
                match target {
                    ClipboardChannelTarget::Primary => v.push(b"-p"),
                    ClipboardChannelTarget::Clipboard => v.push(b"-b"),
                }
                match op {
                    ClipboardChannelOperation::Copy => v.push(b"-i"),
                    ClipboardChannelOperation::Paste => v.push(b"-o"),
                }
            }
            Self::MacOS => match op {
                ClipboardChannelOperation::Copy => v.push(b"pbcopy"),
                ClipboardChannelOperation::Paste => v.push(b"pbpaste"),
            },
        }
        v.iter().map(|&x| x.into()).collect()
    }
}

struct ConfigData {
    detach: bool,
    runtime_dir: PathBuf,
    format: LogFormat,
    config_file: ConfigFile,
    root: Option<bool>,
    clipboard_backend: Option<ClipboardBackend>,
    clipboard_enabled: Option<bool>,
    capability: BTreeSet<Capability>,
    credential_backends: Option<Vec<CredentialBackend>>,
    socket_data: Option<LawnSocketData>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialBackend {
    pub kind: CredentialBackendType,
    pub name: String,
    enabled: bool,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CredentialBackendType {
    Git { command: String },
    Memory { token: Option<String> },
    Other,
}

type EnvFn = dyn FnMut(&str) -> Option<OsString>;

pub struct ConfigBuilder {
    env: Option<Box<EnvFn>>,
    env_vars: Option<Arc<BTreeMap<Bytes, Bytes>>>,
    verbosity: i32,
    config_file: Option<PathBuf>,
    stdout: Option<Box<dyn Write + Sync + Send>>,
    stderr: Option<Box<dyn Write + Sync + Send>>,
    create: bool,
    capabilities: Option<BTreeSet<Capability>>,
    prng: Option<Arc<Mutex<dyn RNG + Send + Sync>>>,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self {
            env: None,
            env_vars: None,
            verbosity: 0,
            config_file: None,
            stdout: None,
            stderr: None,
            create: false,
            capabilities: None,
            prng: None,
        }
    }

    pub fn env<
        E: FnMut(&str) -> Option<OsString> + 'static,
        I: Iterator<Item = (OsString, OsString)>,
        V: FnMut() -> I,
    >(
        &mut self,
        env: E,
        env_iter: V,
    ) -> &mut Self {
        let mut env_iter = env_iter;
        self.env = Some(Box::new(env));
        self.env_vars = Some(Arc::new(
            env_iter()
                .map(|(k, v)| (k.as_bytes().to_vec().into(), v.as_bytes().to_vec().into()))
                .collect(),
        ));
        self
    }

    pub fn verbosity(&mut self, verbosity: i32) -> &mut Self {
        self.verbosity = verbosity;
        self
    }

    pub fn config_file(&mut self, path: &Path) -> &mut Self {
        self.config_file = Some(path.into());
        self
    }

    pub fn stdout(&mut self, stdout: Box<dyn Write + Sync + Send>) -> &mut Self {
        self.stdout = Some(stdout);
        self
    }

    pub fn stderr(&mut self, stderr: Box<dyn Write + Sync + Send>) -> &mut Self {
        self.stderr = Some(stderr);
        self
    }

    pub fn create_runtime_dir(&mut self, create: bool) -> &mut Self {
        self.create = create;
        self
    }

    pub fn prng(&mut self, prng: Arc<Mutex<dyn RNG + Send + Sync>>) -> &mut Self {
        self.prng = Some(prng);
        self
    }

    #[allow(clippy::mutable_key_type)]
    pub fn capabilities(&mut self, capabilities: BTreeSet<Capability>) -> &mut Self {
        self.capabilities = Some(capabilities);
        self
    }

    fn missing_config_option(opt_name: &str) -> Error {
        Error::new_with_message(
            ErrorKind::MissingRequiredConfigOption,
            format!("missing required argument {}", opt_name),
        )
    }

    #[allow(clippy::mutable_key_type)]
    pub fn build(self) -> Result<Config, Error> {
        let stdout = self
            .stdout
            .ok_or_else(|| Self::missing_config_option("stdout"))?;
        let stderr = self
            .stderr
            .ok_or_else(|| Self::missing_config_option("stderr"))?;
        let logger = Logger::new(self.verbosity, stdout, stderr);
        let env = self.env.ok_or_else(|| Self::missing_config_option("env"))?;
        let runtime_dir =
            Config::create_runtime_dir(&logger, env, self.create).ok_or_else(|| {
                Error::new_with_message(
                    ErrorKind::RuntimeDirectoryFailure,
                    "cannot detect runtime directory",
                )
            })?;
        let config_file = {
            match self.config_file {
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
        let env_vars = self
            .env_vars
            .ok_or_else(|| Self::missing_config_option("env"))?;
        let prng = self.prng.unwrap_or_else(|| {
            Arc::new(Mutex::new(rand::rngs::adapter::ReseedingRng::new(
                rand_chacha::ChaCha20Core::from_entropy(),
                0,
                rand::rngs::OsRng,
            )))
        });
        Ok(Config {
            logger: Arc::new(logger),
            data: RwLock::new(ConfigData {
                detach: true,
                runtime_dir,
                format: LogFormat::Text,
                config_file,
                root: None,
                clipboard_backend: None,
                clipboard_enabled: None,
                capability: self.capabilities.unwrap_or_else(Capability::implemented),
                credential_backends: None,
                socket_data: None,
            }),
            env_vars,
            prng,
            template_contexts: Arc::new(RwLock::new(BTreeMap::new())),
        })
    }
}

pub struct TemplateContextGuard {
    template_contexts: Arc<RwLock<BTreeMap<Bytes, Arc<TemplateContext>>>>,
    id: Bytes,
    context: Arc<TemplateContext>,
    logger: Arc<Logger>,
}

impl TemplateContextGuard {
    pub fn context(&self) -> &TemplateContext {
        &self.context
    }

    pub fn context_id(&self) -> Bytes {
        self.id.clone()
    }
}

impl AsRef<TemplateContext> for TemplateContextGuard {
    fn as_ref(&self) -> &TemplateContext {
        &self.context
    }
}

impl Deref for TemplateContextGuard {
    type Target = TemplateContext;

    fn deref(&self) -> &TemplateContext {
        &self.context
    }
}

impl Drop for TemplateContextGuard {
    fn drop(&mut self) {
        trace!(self.logger, "dropping template context {:?}", self.id);
        let mut g = self.template_contexts.write().unwrap();
        g.remove(&self.id);
    }
}

pub struct Config {
    logger: Arc<Logger>,
    data: RwLock<ConfigData>,
    env_vars: Arc<BTreeMap<Bytes, Bytes>>,
    prng: Arc<Mutex<dyn RNG + Send + Sync>>,
    template_contexts: Arc<RwLock<BTreeMap<Bytes, Arc<TemplateContext>>>>,
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
                clipboard_backend: None,
                clipboard_enabled: None,
                capability: Capability::implemented(),
                credential_backends: None,
                socket_data: None,
            }),
            env_vars: Arc::new(
                env_iter()
                    .map(|(k, v)| (k.as_bytes().to_vec().into(), v.as_bytes().to_vec().into()))
                    .collect(),
            ),
            prng: Arc::new(Mutex::new(rand::rngs::adapter::ReseedingRng::new(
                rand_chacha::ChaCha20Core::from_entropy(),
                0,
                rand::rngs::OsRng,
            ))),
            template_contexts: Arc::new(RwLock::new(BTreeMap::new())),
        })
    }

    pub fn set_socket_data(&self, data: LawnSocketData) {
        trace!(self.logger(), "config: setting socket data: {:?}", &data);
        let mut g = self.data.write().unwrap();
        g.socket_data = Some(data);
    }

    pub fn prng(&self) -> Arc<Mutex<dyn RNG + Send + Sync>> {
        self.prng.clone()
    }

    pub fn template_context(
        &self,
        cenv: Option<Arc<BTreeMap<Bytes, Bytes>>>,
        args: Option<Arc<[Bytes]>>,
    ) -> TemplateContextGuard {
        self.template_context_with_data(cenv, args, None::<(&str, &Empty)>)
            .unwrap()
    }

    fn generate_lawn_env(&self, id: Bytes) -> Result<Bytes, Error> {
        let data = self.data.read().unwrap();
        let mut sockdata = match &data.socket_data {
            Some(sockdata) => sockdata.clone(),
            None => {
                return Err(Error::new_with_message(
                    ErrorKind::NoSuchSocket,
                    "cannot find socket data",
                ))
            }
        };
        sockdata.context = Some(id);
        Ok(sockdata.generate_env())
    }

    pub fn template_context_with_data<S: Serialize>(
        &self,
        cenv: Option<Arc<BTreeMap<Bytes, Bytes>>>,
        args: Option<Arc<[Bytes]>>,
        data: Option<(&str, &S)>,
    ) -> Result<TemplateContextGuard, Error> {
        let id = {
            let mut buf = [0u8; 32];
            let mut g = self.prng.lock().unwrap();
            g.fill_bytes(&mut buf);
            Bytes::copy_from_slice(&buf)
        };
        let mut ctxsenv = BTreeMap::new();
        match self.generate_lawn_env(id.clone()) {
            Ok(env) => {
                trace!(self.logger(), "storing LAWN environment variable {:?}", env);
                ctxsenv.insert(Bytes::from(b"LAWN".as_slice()), env);
            }
            Err(_) => {
                debug!(
                    self.logger(),
                    "not generating LAWN environment variable due to missing socket data"
                )
            }
        };
        let (kind, extra) = match data {
            Some((s, obj)) => {
                trace!(
                    self.logger,
                    "creating template context with data of kind {}",
                    s
                );
                let data = serde_cbor::value::to_value(obj)
                    .map_err(|e| Error::new_with_cause(ErrorKind::TemplateError, e))?;
                (Some(s.to_string()), Some(data))
            }
            None => {
                trace!(
                    self.logger,
                    "creating template context with no type-specific data"
                );
                (None, None)
            }
        };
        let ctx = Arc::new(TemplateContext {
            senv: Some(self.env_vars.clone()),
            cenv,
            args,
            ctxsenv: Some(Arc::new(ctxsenv)),
            kind,
            extra,
        });
        {
            let mut g = self.template_contexts.write().unwrap();
            g.insert(id.clone(), ctx.clone());
            trace!(self.logger(), "storing template context {:?}", id)
        }
        Ok(TemplateContextGuard {
            template_contexts: self.template_contexts.clone(),
            id,
            context: ctx,
            logger: self.logger(),
        })
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

    #[allow(clippy::mutable_key_type)]
    pub fn capabilities(&self) -> BTreeSet<Capability> {
        let g = self.data.read().unwrap();
        g.capability.clone()
    }

    pub fn detach(&self) -> bool {
        let g = self.data.read().unwrap();
        g.detach
    }

    pub fn runtime_dir(&self) -> PathBuf {
        let g = self.data.read().unwrap();
        g.runtime_dir.clone()
    }

    #[allow(clippy::mutable_key_type)]
    pub fn template_contexts(&self) -> Arc<RwLock<BTreeMap<Bytes, Arc<TemplateContext>>>> {
        self.template_contexts.clone()
    }

    #[allow(clippy::mutable_key_type)]
    pub fn env_vars(&self) -> &BTreeMap<Bytes, Bytes> {
        &self.env_vars
    }

    pub fn autoprune_sockets(&self) -> bool {
        let g = self.data.read().unwrap();
        g.config_file
            .v0
            .socket
            .as_ref()
            .and_then(|m| m.autoprune)
            .unwrap_or(false)
    }

    pub fn is_root(&self) -> Result<bool, Error> {
        let val = {
            let g = self.data.read().unwrap();
            if let Some(val) = g.root {
                return Ok(val);
            }
            // This is the default algorithm for determining whether we're running in a GUI.  It is
            // subject to change at any time.
            g.config_file.v0.root.clone().unwrap_or_else(|| Value::String("![ -z \"$SSH_TTY\" ] && { [ -n \"$WAYLAND_DISPLAY\" ] || [ -n \"$DISPLAY\" ] || [ \"$(uname -s)\" = Darwin ]; }".to_string()))
        };
        let ctx = self.template_context(None, None);
        let result = ConfigValue::new(val, &ctx)?.into_bool()?;
        let mut g = self.data.write().unwrap();
        g.root = Some(result);
        Ok(result)
    }

    pub fn p9p_enabled(&self, name: &str) -> Result<bool, Error> {
        let val = {
            let g = self.data.read().unwrap();
            let p9p_value = g.config_file.v0.p9p.as_ref().and_then(|p| p.get(name));
            match p9p_value {
                Some(v) => v.if_value.clone(),
                None => return self.fs_enabled(name),
            }
        };
        let ctx = self.template_context(None, None);
        ConfigValue::new(val, &ctx)?.into_bool()
    }

    pub fn fs_enabled(&self, name: &str) -> Result<bool, Error> {
        let val = {
            let g = self.data.read().unwrap();
            match g
                .config_file
                .v0
                .fs
                .as_ref()
                .and_then(|p| p.get(name))
                .map(|x| x.if_value.clone())
            {
                Some(v) => v,
                None => Value::Bool(false),
            }
        };
        let ctx = self.template_context(None, None);
        ConfigValue::new(val, &ctx)?.into_bool()
    }

    pub fn p9p_location(&self, name: &str) -> Result<Option<String>, Error> {
        let val = {
            let g = self.data.read().unwrap();
            let p9p_value = g.config_file.v0.p9p.as_ref().and_then(|p| p.get(name));
            let p9pcfg = match p9p_value {
                Some(c) => c,
                None => return self.fs_location(name),
            };
            match p9pcfg.location.clone() {
                Some(Value::String(ref s)) => s.clone(),
                None => return Ok(None),
                _ => return Err(Error::new(ErrorKind::InvalidConfigurationValue)),
            }
        };
        let ctx = self.template_context(None, None);
        let val = Value::String(val);
        Ok(Some(ConfigValue::new(val, &ctx)?.into_string()?))
    }

    pub fn fs_location(&self, name: &str) -> Result<Option<String>, Error> {
        let val = {
            let g = self.data.read().unwrap();
            match g
                .config_file
                .v0
                .fs
                .as_ref()
                .and_then(|p| p.get(name))
                .and_then(|x| x.location.clone())
            {
                Some(Value::String(ref s)) => s.clone(),
                None => return Ok(None),
                _ => return Err(Error::new(ErrorKind::InvalidConfigurationValue)),
            }
        };
        let ctx = self.template_context(None, None);
        let val = Value::String(val);
        Ok(Some(ConfigValue::new(val, &ctx)?.into_string()?))
    }

    pub fn proxy_poll_timeout(&self) -> Duration {
        let val = {
            let g = self.data.read().unwrap();
            g.config_file
                .v0
                .proxy
                .as_ref()
                .and_then(|v| v.ssh.as_ref())
                .and_then(|v| v.timeout.as_ref())
                .and_then(|v| v.poll_ms)
                .unwrap_or(50)
        };
        Duration::from_millis(val)
    }

    pub fn proxy_server_read_timeout(&self) -> Duration {
        let val = {
            let g = self.data.read().unwrap();
            g.config_file
                .v0
                .proxy
                .as_ref()
                .and_then(|v| v.ssh.as_ref())
                .and_then(|v| v.timeout.as_ref())
                .and_then(|v| v.server_read_ms)
                .unwrap_or(15)
        };
        Duration::from_millis(val)
    }

    fn clipboard_command_from_str(s: &str) -> Option<ClipboardBackend> {
        match s {
            "xclip" => Some(ClipboardBackend::XClip),
            "xsel" => Some(ClipboardBackend::XSel),
            "macos" => Some(ClipboardBackend::MacOS),
            _ => None,
        }
    }

    fn compute_credential_backends(&self) -> Result<(), Error> {
        let g = self.data.read().unwrap();
        if g.credential_backends.is_some() {
            return Ok(());
        }
        let val = match g
            .config_file
            .v0
            .credential
            .as_ref()
            .map(|x| x.if_value.clone())
        {
            Some(v) => v,
            None => Value::Bool(false),
        };
        let ctx = self.template_context(None, None);
        let result = ConfigValue::new(val, &ctx)?.into_bool()?;
        let backends = {
            let config_backends = if result {
                g.config_file
                    .v0
                    .credential
                    .as_ref()
                    .and_then(|c| c.backends.as_deref())
                    .unwrap_or_default()
            } else {
                &[]
            };
            config_backends
                .iter()
                .map(|b| {
                    let val = b.if_value.clone().unwrap_or(Value::Bool(false));
                    let ctx = self.template_context(None, None);
                    let result = ConfigValue::new(val, &ctx)?.into_bool()?;
                    let kind = match (b.kind.as_ref(), &b.options) {
                        ("git", Some(opts)) => match opts.get("command") {
                            Some(Value::String(ref s)) => {
                                CredentialBackendType::Git { command: s.clone() }
                            }
                            _ => {
                                return Err(Error::new_with_message(
                                    ErrorKind::InvalidConfigurationValue,
                                    "credential type \"git\" requires the option \"command\"",
                                ))
                            }
                        },
                        ("memory", None) => CredentialBackendType::Memory { token: None },
                        ("memory", Some(opts)) => match opts.get("token") {
                            Some(Value::String(ref s)) => {
                                CredentialBackendType::Memory { token: Some(s.clone()) }
                            },
                            None => CredentialBackendType::Memory { token: None },
                            _ => {
                                return Err(Error::new_with_message(
                                    ErrorKind::InvalidConfigurationValue,
                                    "credential type \"memory\" requires the option \"token\" to be a string",
                                ))
                            }
                        },
                        ("git", None) => {
                            return Err(Error::new_with_message(
                                ErrorKind::InvalidConfigurationValue,
                                "credential type \"git\" requires the option \"command\"",
                            ))
                        }
                        _ => CredentialBackendType::Other,
                    };
                    Ok(CredentialBackend {
                        kind,
                        name: b.name.clone(),
                        enabled: result,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?
        };
        std::mem::drop(g);
        let mut g = self.data.write().unwrap();
        g.credential_backends = Some(backends);
        Ok(())
    }

    pub fn credential_backends(&self) -> Result<Vec<CredentialBackend>, Error> {
        self.compute_credential_backends()?;
        let g = self.data.read().unwrap();
        if let Some(ref val) = g.credential_backends {
            return Ok(val
                .iter()
                .filter(|b| b.enabled && b.kind != CredentialBackendType::Other)
                .cloned()
                .collect());
        }
        Ok(vec![])
    }

    pub fn credential_backends_as_map(&self) -> Result<BTreeMap<String, CredentialBackend>, Error> {
        self.compute_credential_backends()?;
        let g = self.data.read().unwrap();
        if let Some(ref val) = g.credential_backends {
            return Ok(val
                .iter()
                .filter(|b| b.enabled && b.kind != CredentialBackendType::Other)
                .cloned()
                .map(|b| (b.name.clone(), b))
                .collect());
        }
        Ok(BTreeMap::new())
    }

    pub fn credential_backend_control<S: Serialize>(
        &self,
        args: Arc<[Bytes]>,
        data: Option<&S>,
    ) -> Result<Option<String>, Error> {
        let g = self.data.read().unwrap();
        let val = match g
            .config_file
            .v0
            .credential
            .as_ref()
            .and_then(|x| x.control.clone())
        {
            Some(v) => v,
            None => return Ok(None),
        };
        let data = data.map(|d| ("credential", d));
        trace!(
            self.logger,
            "querying credential backend with context: {}",
            if data.is_some() { "Some" } else { "None" }
        );
        let ctx = self.template_context_with_data(None, Some(args), data)?;
        let val = Value::String(val);
        Ok(Some(ConfigValue::new(val, &ctx)?.into_string()?))
    }

    pub fn clipboard_enabled(&self) -> Result<bool, Error> {
        let val = {
            let g = self.data.read().unwrap();
            if let Some(val) = g.clipboard_enabled {
                return Ok(val);
            }
            match g
                .config_file
                .v0
                .clipboard
                .as_ref()
                .map(|x| x.if_value.clone())
            {
                Some(v) => v,
                None => Value::Bool(false),
            }
        };
        let ctx = self.template_context(None, None);
        let result = ConfigValue::new(val, &ctx)?.into_bool()?;
        let mut g = self.data.write().unwrap();
        g.clipboard_enabled = Some(result);
        Ok(result)
    }

    pub fn clipboard_backend(&self) -> Result<Option<ClipboardBackend>, Error> {
        let val = {
            let g = self.data.read().unwrap();
            if let Some(val) = g.clipboard_backend {
                return Ok(Some(val));
            }
            match g
                .config_file
                .v0
                .clipboard
                .as_ref()
                .and_then(|x| x.backend.clone())
            {
                Some(Value::String(ref s)) => {
                    if let Some(backend) = Self::clipboard_command_from_str(s) {
                        return Ok(Some(backend));
                    } else if s.starts_with('!') {
                        s.to_string()
                    } else if s == "default" {
                        "!f() { if command -v pbcopy >/dev/null 2>&1 && command -v pbpaste >/dev/null 2>&1; then echo macos; elif command -v xclip >/dev/null 2>&1; then echo xclip; elif command -v xsel >/dev/null 2>&1; then echo xsel; fi; };f".to_string()
                    } else {
                        return Err(Error::new(ErrorKind::InvalidConfigurationValue));
                    }
                }
                None => return Ok(None),
                _ => return Err(Error::new(ErrorKind::InvalidConfigurationValue)),
            }
        };
        let ctx = self.template_context(None, None);
        let val = Value::String(val);
        let result = ConfigValue::new(val, &ctx)?.into_string()?;
        let backend = Self::clipboard_command_from_str(&result);
        let mut g = self.data.write().unwrap();
        g.clipboard_backend = backend;
        Ok(backend)
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
            buf.push("lawn");
            logger.trace(&format!("runtime_dir: found, using {:?}", buf));
            v.push(buf);
        }
        logger.trace("runtime_dir: looking for HOME");
        if let Some(dir) = env("HOME") {
            let mut buf: PathBuf = dir.into();
            buf.push(".local");
            buf.push("run");
            buf.push("lawn");
            logger.trace(&format!("runtime_dir: found, using {:?}", buf));
            v.push(buf);
        }
        let mut m = HashSet::new();
        v.iter()
            .filter(|&x| {
                if m.contains(x) {
                    false
                } else {
                    m.insert(x.clone());
                    true
                }
            })
            .cloned()
            .collect()
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
        match Self::find_runtime_dirs(logger, env).first() {
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

#[derive(Serialize)]
struct SerializedError {
    error: SerializedInternalError,
}

#[derive(Serialize)]
struct SerializedInternalError {
    types: Vec<String>,
    tag: String,
    message: String,
}

impl<T: ExtendedError + std::error::Error> From<&T> for SerializedError {
    fn from(err: &T) -> SerializedError {
        SerializedError {
            error: SerializedInternalError {
                types: err.error_types().iter().map(|s| s.to_string()).collect(),
                tag: err.error_tag().to_string(),
                message: format!("{}", err),
            },
        }
    }
}

pub struct Logger {
    output: Mutex<Box<dyn Write + Sync + Send>>,
    error: Mutex<Box<dyn Write + Sync + Send>>,
    verbosity: i32,
    level: LogLevel,
    format: RwLock<LogFormat>,
    encoder: ScriptEncoder,
    tag_counter: AtomicU32,
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
            4 => LogLevel::Dump,
            _ => LogLevel::Dump,
        };
        Self {
            output: Mutex::new(output),
            error: Mutex::new(error),
            verbosity,
            level,
            format: RwLock::new(LogFormat::Text),
            encoder: ScriptEncoder::new(),
            tag_counter: AtomicU32::new(0),
        }
    }

    fn write(&self, desired: i32, io: &Mutex<Box<dyn Write + Sync + Send>>, msg: &str) {
        self.write_bytes(desired, io, msg.as_bytes())
    }

    fn write_bytes(&self, desired: i32, io: &Mutex<Box<dyn Write + Sync + Send>>, msg: &[u8]) {
        if self.verbosity >= desired {
            let mut m = io.lock().unwrap();
            let _ = m.write_all(msg);
        }
    }

    fn set_format(&self, format: LogFormat) {
        let mut g = self.format.write().unwrap();
        *g = format;
    }

    fn gen_tag<'a>(&self, buf: &'a mut [u8; 16]) -> &'a [u8] {
        let val = self.tag_counter.fetch_add(1, Ordering::AcqRel);
        let mut c = std::io::Cursor::new(buf.as_mut_slice());
        let _ = write!(c, "_x{:08x}", val);
        &buf[..10]
    }

    pub fn script_message_bytes(&self, tag: Option<&[u8]>, msg: &[Bytes]) {
        let mut buf = [0u8; 16];
        let tag = tag.unwrap_or_else(|| self.gen_tag(&mut buf));
        let mut io = self.output.lock().unwrap();
        let _ = io.write_all(tag);
        let _ = io.write_all(b" ok ");
        for (i, val) in msg.iter().enumerate() {
            let _ = io.write_all(val.as_ref());
            if i != msg.len() - 1 {
                let _ = io.write_all(b" ");
            }
        }
        let _ = io.write_all(b"\n");
        let _ = io.flush();
    }

    pub fn message_bytes(&self, msg: &[u8]) {
        let format = {
            let g = self.format.read().unwrap();
            *g
        };
        if format == LogFormat::Text {
            self.write_bytes(0, &self.output, &format_bytes!(b"{}\n", msg));
        }
    }
}

impl lawn_protocol::config::Logger for Logger {
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
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|e| e.duration());
        self.write(
            3,
            &self.error,
            &format!("trace: {:09.9}: {}\n", time.as_secs_f64(), msg),
        );
    }

    fn script_message(&self, tag: Option<&[u8]>, msg: &[&[u8]]) {
        let mut buf = [0u8; 16];
        let tag = tag.unwrap_or_else(|| self.gen_tag(&mut buf));
        let mut io = self.output.lock().unwrap();
        let _ = io.write_all(tag);
        let _ = io.write_all(b" ok ");
        for (i, val) in msg.iter().enumerate() {
            let _ = io.write_all(val.as_ref());
            if i != msg.len() - 1 {
                let _ = io.write_all(b" ");
            }
        }
        let _ = io.write_all(b"\n");
        let _ = io.flush();
    }

    fn script_error(&self, tag: Option<&[u8]>, err: &dyn ExtendedError) {
        let mut buf = [0u8; 16];
        let tag = tag.unwrap_or_else(|| self.gen_tag(&mut buf));
        let mut io = self.output.lock().unwrap();
        let _ = io.write_all(tag);
        let _ = io.write_all(b" err ");
        let error_types = err.error_types();
        let error_types: &[Cow<'static, str>] = error_types.borrow();
        let error_types = error_types.join(":");
        let _ = io.write_all(error_types.as_bytes());
        let _ = io.write_all(b" ");
        let _ = io.write_all(err.error_tag().as_bytes());
        let _ = io.write_all(b" ");
        let _ = io.write_all(self.encoder.encode(&format!("{}", err)).borrow());
        let _ = io.write_all(b"\n");
        let _ = io.flush();
    }

    fn serialized(&self, msg: &[u8]) {
        if self.format() == LogFormat::CBOR {
            self.write_bytes(0, &self.output, msg);
        }
    }

    fn serialized_error(&self, err: &dyn ExtendedError) {
        if self.format() == LogFormat::CBOR {
            let err = SerializedError::from(&err);
            match serde_cbor::to_vec(&err) {
                Ok(msg) => self.serialized_message(&msg),
                Err(e) => error!(self, "error serializing CBOR: {}", e),
            }
        }
    }
}

pub trait SerializedLogger {
    fn serialized_message<S: serde::Serialize>(&self, msg: &S);
}

impl<T: LoggerTrait> SerializedLogger for T {
    fn serialized_message<S: serde::Serialize>(&self, msg: &S) {
        if self.format() == LogFormat::CBOR {
            match serde_cbor::to_vec(msg) {
                Ok(msg) => self.serialized_message(&msg),
                Err(e) => error!(self, "error serializing CBOR: {}", e),
            }
        }
    }
}

pub struct ConfigValue<'a> {
    value: Value,
    context: &'a TemplateContext,
}

impl<'a> ConfigValue<'a> {
    pub fn new(value: Value, context: &'a TemplateContext) -> Result<ConfigValue<'a>, Error> {
        Ok(ConfigValue { value, context })
    }

    fn templatize(s: &str, context: &'a TemplateContext) -> Result<Bytes, Error> {
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

    fn into_bool(self) -> Result<bool, Error> {
        let command = match self.value {
            Value::Bool(b) => return Ok(b),
            Value::String(ref s) => s,
            _ => return Err(Error::new(ErrorKind::InvalidConfigurationValue)),
        };
        let mut cmd = self.create_command(&Self::templatize(command, self.context)?);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(_) => return Ok(false),
        };
        match child.wait() {
            Ok(es) => Ok(es.success()),
            Err(_) => Ok(false),
        }
    }

    fn into_string(self) -> Result<String, Error> {
        let s = match self.value {
            Value::String(ref s) => s,
            _ => return Err(Error::new(ErrorKind::InvalidConfigurationValue)),
        };
        if !s.starts_with('!') {
            return Ok(s.into());
        }
        let mut cmd = self.create_command(&Self::templatize(s, self.context)?);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::null());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(_) => return Ok(String::new()),
        };
        let mut s = String::new();
        if child
            .stdout
            .as_mut()
            .unwrap()
            .read_to_string(&mut s)
            .is_err()
        {
            return Err(Error::new(ErrorKind::ConfigurationSpawnError));
        }
        let _ = child.wait();
        Ok(s.trim_end_matches(|c| c == '\n').into())
    }

    fn create_command(&self, shell: &Bytes) -> std::process::Command {
        let mut shell: BytesMut = shell.as_ref().into();
        if self.context.args.is_some() {
            shell.extend_from_slice(b" \"$@\"");
        }
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c");
        cmd.arg(OsStr::from_bytes(&shell));
        if let Some(args) = &self.context.args {
            for arg in args.iter() {
                cmd.arg(OsString::from_vec(arg.to_vec()));
            }
        }
        if let Some(senv) = &self.context.senv {
            cmd.env_clear();
            cmd.envs(senv.iter().map(|(k, v)| {
                (
                    OsString::from_vec(k.to_vec()),
                    OsString::from_vec(v.to_vec()),
                )
            }));
        }
        if let Some(ctxsenv) = &self.context.ctxsenv {
            cmd.envs(ctxsenv.iter().map(|(k, v)| {
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

pub fn command_from_shell(shell: &Bytes, context: &TemplateContext) -> tokio::process::Command {
    let mut shell: BytesMut = shell.as_ref().into();
    shell.extend_from_slice(b" \"$@\"");
    command_from_args(
        &[
            (b"sh" as &'static [u8]).into(),
            (b"-c" as &'static [u8]).into(),
            shell.into(),
        ],
        context,
    )
}

pub fn std_command_from_shell(shell: &Bytes, context: &TemplateContext) -> std::process::Command {
    let mut shell: BytesMut = shell.as_ref().into();
    shell.extend_from_slice(b" \"$@\"");
    std_command_from_args(
        &[
            (b"sh" as &'static [u8]).into(),
            (b"-c" as &'static [u8]).into(),
            shell.into(),
        ],
        context,
    )
}

pub fn command_from_args(args: &[Bytes], context: &TemplateContext) -> tokio::process::Command {
    let args: Vec<OsString> = args
        .iter()
        .map(|x| OsString::from_vec(x.to_vec()))
        .collect();
    let mut cmd = tokio::process::Command::new(&args[0]);
    if args.len() > 1 {
        cmd.args(&args[1..]);
    }
    if let Some(args) = &context.args {
        for arg in args.iter() {
            cmd.arg(OsString::from_vec(arg.to_vec()));
        }
    }
    if let Some(senv) = &context.senv {
        cmd.env_clear();
        cmd.envs(senv.iter().map(|(k, v)| {
            (
                OsString::from_vec(k.to_vec()),
                OsString::from_vec(v.to_vec()),
            )
        }));
    }
    if let Some(ctxsenv) = &context.ctxsenv {
        cmd.envs(ctxsenv.iter().map(|(k, v)| {
            (
                OsString::from_vec(k.to_vec()),
                OsString::from_vec(v.to_vec()),
            )
        }));
    }
    cmd.current_dir("/");
    cmd
}

pub fn std_command_from_args(args: &[Bytes], context: &TemplateContext) -> std::process::Command {
    let args: Vec<OsString> = args
        .iter()
        .map(|x| OsString::from_vec(x.to_vec()))
        .collect();
    let mut cmd = std::process::Command::new(&args[0]);
    if args.len() > 1 {
        cmd.args(&args[1..]);
    }
    if let Some(args) = &context.args {
        for arg in args.iter() {
            cmd.arg(OsString::from_vec(arg.to_vec()));
        }
    }
    if let Some(senv) = &context.senv {
        cmd.env_clear();
        cmd.envs(senv.iter().map(|(k, v)| {
            (
                OsString::from_vec(k.to_vec()),
                OsString::from_vec(v.to_vec()),
            )
        }));
    }
    if let Some(ctxsenv) = &context.ctxsenv {
        cmd.envs(ctxsenv.iter().map(|(k, v)| {
            (
                OsString::from_vec(k.to_vec()),
                OsString::from_vec(v.to_vec()),
            )
        }));
    }
    cmd.current_dir("/");
    cmd
}

pub struct Command<'a> {
    condition: Option<Value>,
    pre: Vec<Bytes>,
    post: Vec<Bytes>,
    command: Bytes,
    context: &'a TemplateContext,
}

impl<'a> Command<'a> {
    pub fn new(config: &ConfigCommand, context: &'a TemplateContext) -> Result<Command<'a>, Error> {
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
            condition: Some(config.if_value.clone()),
            pre,
            post,
            command: Self::templatize(&config.command, context)?,
            context,
        })
    }

    pub fn new_simple(command: &str, context: &'a TemplateContext) -> Result<Command<'a>, Error> {
        Ok(Command {
            condition: Some(Value::Bool(true)),
            pre: vec![],
            post: vec![],
            command: Self::templatize(command, context)?,
            context,
        })
    }

    fn templatize(s: &str, context: &'a TemplateContext) -> Result<Bytes, Error> {
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

    async fn run_one(&self, shell: &Bytes) -> Result<i32, Error> {
        if shell == b"true" as &[u8] {
            return Ok(0);
        } else if shell == b"false" as &[u8] {
            return Ok(1);
        }
        let mut cmd = command_from_shell(shell, self.context);
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
        command_from_shell(&self.command, self.context)
    }

    pub fn run_std_command(&self) -> std::process::Command {
        std_command_from_shell(&self.command, self.context)
    }

    pub async fn check_condition(&self) -> Result<bool, Error> {
        match &self.condition {
            Some(condition) => ConfigValue::new(condition.clone(), self.context)?.into_bool(),
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
                clipboard: None,
                socket: None,
                commands: None,
                credential: None,
                p9p: None,
                fs: None,
                proxy: None,
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ConfigFileV0 {
    root: Option<Value>,
    clipboard: Option<ConfigClipboard>,
    socket: Option<ConfigSockets>,
    commands: Option<BTreeMap<String, ConfigCommand>>,
    credential: Option<ConfigCredential>,
    #[serde(rename = "9p")]
    p9p: Option<BTreeMap<String, Config9P>>,
    fs: Option<BTreeMap<String, ConfigFS>>,
    proxy: Option<ConfigProxy>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigProxy {
    ssh: Option<ConfigProxySSH>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigProxySSH {
    timeout: Option<ConfigProxySSHTimeout>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename = "kebab-case")]
pub struct ConfigProxySSHTimeout {
    poll_ms: Option<u64>,
    server_read_ms: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigClipboard {
    #[serde(rename = "if")]
    if_value: Value,
    backend: Option<Value>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigSockets {
    autoprune: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigCommand {
    #[serde(rename = "if")]
    if_value: Value,
    command: String,
    #[serde(rename = "pre")]
    pre: Option<Vec<String>>,
    #[serde(rename = "post")]
    post: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Config9P {
    #[serde(rename = "if")]
    if_value: Value,
    location: Option<Value>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFS {
    #[serde(rename = "if")]
    if_value: Value,
    location: Option<Value>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigCredential {
    #[serde(rename = "if")]
    if_value: Value,
    control: Option<String>,
    backends: Option<Vec<ConfigCredentialBackend>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigCredentialBackend {
    #[serde(rename = "if")]
    if_value: Option<Value>,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    options: Option<BTreeMap<String, Value>>,
}

#[cfg(test)]
mod tests {
    use super::{Config, ConfigFile};
    use lawn_constants::error::ExtendedError;
    use lawn_constants::logger::{LogFormat, LogLevel, Logger};
    #[cfg(not(miri))]
    use serde_yaml::Value;
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
        env.insert("XDG_RUNTIME_DIR".into(), "/tmp".into());
        let env2 = env.clone();
        let cfg = Config::new(
            |var| env2.get(&OsString::from(var)).map(|x| x.clone()),
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

    #[cfg(not(miri))]
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

    #[cfg(not(miri))]
    #[test]
    fn is_root_with_values() {
        let cfg = config_with_values(BTreeMap::new(), |c| {
            c.v0.root = Some(Value::String("!command true".into()))
        });
        assert_eq!(cfg.is_root().unwrap(), true);

        let cfg = config_with_values(BTreeMap::new(), |c| c.v0.root = Some(Value::Bool(true)));
        assert_eq!(cfg.is_root().unwrap(), true);

        let cfg = config_with_values(BTreeMap::new(), |c| {
            c.v0.root = Some(Value::String("!command false".into()))
        });
        assert_eq!(cfg.is_root().unwrap(), false);

        let cfg = config_with_values(BTreeMap::new(), |c| c.v0.root = Some(Value::Bool(false)));
        assert_eq!(cfg.is_root().unwrap(), false);

        let cfg = config_with_values(BTreeMap::new(), |c| {
            c.v0.root = Some("!cat /dev/null".into())
        });
        assert_eq!(cfg.is_root().unwrap(), true);
    }

    struct PanicLogger {
        level: LogLevel,
    }

    impl Logger for PanicLogger {
        fn level(&self) -> LogLevel {
            self.level
        }

        fn format(&self) -> LogFormat {
            LogFormat::Text
        }

        fn fatal(&self, _msg: &str) {
            panic!("fatal");
        }

        fn error(&self, _msg: &str) {
            panic!("error");
        }

        fn message(&self, _msg: &str) {
            panic!("message");
        }

        fn info(&self, _msg: &str) {
            panic!("info");
        }

        fn debug(&self, _msg: &str) {
            panic!("debug");
        }

        fn trace(&self, _msg: &str) {
            panic!("trace");
        }

        fn script_message(&self, _tag: Option<&[u8]>, _msg: &[&[u8]]) {
            panic!("script_message");
        }

        fn script_error(&self, _tag: Option<&[u8]>, _err: &dyn ExtendedError) {
            panic!("script_error");
        }

        fn serialized(&self, _msg: &[u8]) {
            panic!("serialized");
        }

        fn serialized_error(&self, _msg: &dyn ExtendedError) {
            panic!("serialized_error");
        }
    }

    #[test]
    fn skips_calls() {
        let logger = PanicLogger {
            level: LogLevel::Debug,
        };
        trace!(logger, "this should never be invoked");
        let body: Option<u32> = None;
        trace!(logger, "nor should this: {:?}", body.unwrap());
    }
}
