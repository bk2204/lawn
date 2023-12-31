use crate::config::Config;
use crate::error::{Error, ErrorKind};
use crate::ssh_proxy;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use lawn_constants::logger::AsLogStr;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use tokio::runtime::Handle;

#[derive(Default, Serialize, Deserialize, PartialEq, Eq, Copy, Clone, Debug, Hash)]
pub enum LawnSocketKind {
    #[default]
    #[serde(rename = "lawn")]
    Lawn,
    #[serde(rename = "ssh")]
    SSHProxy,
}

impl fmt::Display for LawnSocketKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LawnSocketKind::Lawn => write!(f, "Lawn socket"),
            LawnSocketKind::SSHProxy => write!(f, "SSH proxy socket"),
        }
    }
}

impl FromStr for LawnSocketKind {
    type Err = UnknownSocketKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "lawn" => Ok(LawnSocketKind::Lawn),
            "ssh" => Ok(LawnSocketKind::SSHProxy),
            _ => Err(UnknownSocketKind(s.into())),
        }
    }
}

#[derive(Debug)]
pub struct UnknownSocketKind(String);

impl fmt::Display for UnknownSocketKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown socket kind: {}", self.0)
    }
}

impl std::error::Error for UnknownSocketKind {}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct LawnSocketData {
    #[serde(rename = "sk")]
    kind: LawnSocketKind,
    #[serde(rename = "sock")]
    path: Bytes,
    #[serde(rename = "ctx")]
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<Bytes>,
    #[serde(rename = "auth")]
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<Bytes>,
    #[serde(rename = "user")]
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<Bytes>,
    #[serde(rename = "pass")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pass: Option<Bytes>,
}

pub struct LawnSocketDiscoverer<'a> {
    config: Arc<Config>,
    handle: &'a Handle,
    connection_test: bool,
}

impl<'a> LawnSocketDiscoverer<'a> {
    pub fn new(config: Arc<Config>, handle: &'a Handle) -> Self {
        Self {
            config,
            handle,
            connection_test: true,
        }
    }

    #[allow(dead_code)]
    fn new_for_test(config: Arc<Config>, handle: &'a Handle) -> Self {
        Self {
            config,
            handle,
            connection_test: false,
        }
    }

    pub fn socket_from_path(&self, path: &OsStr) -> Option<LawnSocket> {
        let logger = self.config.logger();
        debug!(
            logger,
            "trying specified socket {}",
            path.as_bytes().as_log_str()
        );
        self.socket(LawnSocketKind::Lawn, path)
    }

    pub fn socket_from_lawn_environment(&self, env_data: &[u8]) -> Option<LawnSocket> {
        self.socket_from_lawn_environment_extended(env_data, false)
    }

    fn socket_from_lawn_environment_extended(
        &self,
        env_data: &[u8],
        unknown_fields: bool,
    ) -> Option<LawnSocket> {
        let logger = self.config.logger();
        debug!(logger, "parsing socket from environment");
        let mut items = env_data.splitn(3, |b| *b == b':');
        match items.next() {
            Some(b"v0") => {
                trace!(logger, "found v0 socket info");
            }
            _ => return None,
        }
        match (items.next(), items.next()) {
            // "s" for "simple socket".
            (Some(b"s"), Some(socket_path)) => {
                trace!(
                    logger,
                    "found v0 simple socket with path {}",
                    socket_path.as_log_str()
                );
                let path = OsStr::from_bytes(socket_path);
                self.socket_from_path(path)
            }
            // "c" for "CBOR".  This is url64-encoded.
            (Some(b"c"), Some(cbor)) => {
                trace!(logger, "found v0 url64-encoded CBOR metadata");
                let cbor = URL_SAFE_NO_PAD.decode(cbor).ok()?;
                trace!(logger, "v0 url64-encoded CBOR metadata decoded ok");
                let data: Result<LawnSocketData, _> = serde_cbor::from_slice(&cbor);
                match data {
                    Ok(data) => {
                        if !unknown_fields
                            && (data.auth.is_some()
                                || data.username.is_some()
                                || data.pass.is_some())
                        {
                            None
                        } else {
                            self.socket_from_data(data)
                        }
                    }
                    Err(e) => {
                        trace!(logger, "failed to decode CBOR metadata: {}", e);
                        None
                    }
                }
            }
            (Some(kind), _) => {
                trace!(
                    logger,
                    "failed to decode environment type: {}",
                    kind.as_log_str()
                );
                None
            }
            _ => {
                trace!(logger, "truncated socket value");
                None
            }
        }
    }

    fn probe_ssh_socket(&self, path: &[u8]) -> Option<UnixStream> {
        let logger = self.config.logger();
        debug!(logger, "trying SSH socket {}", path.as_log_str());
        let path = OsStr::from_bytes(&path);
        match UnixStream::connect(path) {
            Ok(sock) => {
                let log = logger.clone();
                let cfg = self.config.clone();
                let res = self.handle.block_on(async move {
                    debug!(log, "SSH socket: performing client probe");
                    ssh_proxy::Proxy::client_probe(cfg.clone(), sock).await
                });
                match res {
                    Ok(sock) => Some(sock),
                    Err(_) => {
                        debug!(logger, "failed to connect to SSH socket");
                        None
                    }
                }
            }
            Err(e) => {
                debug!(logger, "SSH socket: failed to connect: {}", e);
                None
            }
        }
    }

    pub fn autodiscover(&self, prune: bool) -> Option<LawnSocket> {
        let logger = self.config.logger();
        debug!(logger, "performing socket autodiscovery");
        let ctx = self.config.template_context(None, None);
        let senv = ctx.senv.as_deref().unwrap();
        if let Some(value) = senv.get(b"LAWN" as &[u8]) {
            debug!(logger, "trying LAWN environment variable");
            if let Some(data) = self.socket_from_lawn_environment(&value) {
                if data.kind() == LawnSocketKind::SSHProxy {
                    if let Some(sock) = self.probe_ssh_socket(data.path().as_bytes()) {
                        return Some(LawnSocket {
                            config: self.config.clone(),
                            socket: Some(sock),
                            lawn_socket: None,
                            data: data.data,
                        });
                    }
                } else {
                    return Some(data);
                }
            }
        }
        if let Some(path) = senv.get(b"SSH_AUTH_SOCK" as &[u8]) {
            if let Some(sock) = self.probe_ssh_socket(path) {
                let path = OsStr::from_bytes(&path);
                return Some(LawnSocket {
                    config: self.config.clone(),
                    socket: Some(sock),
                    lawn_socket: None,
                    data: LawnSocketData {
                        path: path.as_bytes().to_owned().into(),
                        kind: LawnSocketKind::SSHProxy,
                        ..Default::default()
                    },
                });
            }
        }
        let mut wanted = None;
        for p in self.config.sockets() {
            match p.file_name() {
                Some(file) => {
                    if !file.as_bytes().starts_with(b"server") {
                        continue;
                    }
                }
                None => continue,
            }
            trace!(
                logger,
                "trying socket {}",
                p.as_os_str().as_bytes().as_log_str()
            );
            match UnixStream::connect(&p) {
                Ok(sock) => {
                    debug!(
                        logger,
                        "successfully connected to socket {}",
                        p.as_os_str().as_bytes().as_log_str(),
                    );
                    if wanted.is_none() {
                        wanted = Some(LawnSocket {
                            socket: Some(sock),
                            data: LawnSocketData {
                                path: p.as_os_str().as_bytes().to_owned().into(),
                                kind: LawnSocketKind::Lawn,
                                ..Default::default()
                            },
                            config: self.config.clone(),
                            lawn_socket: None,
                        });
                    }
                }
                Err(e) => match wanted {
                    Some(_) => {
                        if prune {
                            self.prune_socket(&p);
                        }
                    }
                    None => {
                        debug!(
                            logger,
                            "failed to connect to socket {}: {}",
                            p.as_os_str().as_bytes().as_log_str(),
                            e
                        );
                        if prune {
                            self.prune_socket(&p);
                        }
                    }
                },
            }
        }
        wanted
    }

    fn prune_socket(&self, path: &Path) {
        let logger = self.config.logger();
        trace!(
            logger,
            "autopruning socket {}",
            path.as_os_str().as_bytes().as_log_str()
        );
        let _ = std::fs::remove_file(path);
    }

    fn socket(&self, kind: LawnSocketKind, path: &OsStr) -> Option<LawnSocket> {
        if !self.connection_test {
            return Some(LawnSocket {
                data: LawnSocketData {
                    path: path.as_bytes().to_owned().into(),
                    kind,
                    ..Default::default()
                },
                socket: None,
                config: self.config.clone(),
                lawn_socket: None,
            });
        }
        match UnixStream::connect(path) {
            Ok(sock) => Some(LawnSocket {
                data: LawnSocketData {
                    path: path.as_bytes().to_owned().into(),
                    kind,
                    ..Default::default()
                },
                socket: Some(sock),
                config: self.config.clone(),
                lawn_socket: None,
            }),
            Err(_) => None,
        }
    }

    fn socket_from_data(&self, data: LawnSocketData) -> Option<LawnSocket> {
        if !self.connection_test {
            return Some(LawnSocket {
                data,
                socket: None,
                config: self.config.clone(),
                lawn_socket: None,
            });
        }
        match UnixStream::connect(OsStr::from_bytes(&data.path)) {
            Ok(sock) => Some(LawnSocket {
                data,
                socket: Some(sock),
                config: self.config.clone(),
                lawn_socket: None,
            }),
            Err(_) => None,
        }
    }
}

pub struct LawnSocket {
    data: LawnSocketData,
    socket: Option<UnixStream>,
    config: Arc<Config>,
    lawn_socket: Option<UnixStream>,
}

impl LawnSocket {
    pub fn spawn_proxies(&mut self, handle: &Handle) -> Result<(), Error> {
        if self.data.kind != LawnSocketKind::SSHProxy {
            return Ok(());
        }
        let config = self.config.clone();
        let _eg = handle.enter();
        let (sa, sb) = tokio::net::UnixStream::pair().unwrap();
        let socket = match self.socket.take() {
            Some(socket) => socket,
            None => {
                return Err(Error::new_with_message(
                    ErrorKind::SocketConnectionFailure,
                    "missing socket for proxy",
                ))
            }
        };
        let _ = socket.set_nonblocking(true);
        tokio::spawn(async {
            let p = ssh_proxy::Proxy::new(
                config,
                None,
                sa,
                tokio::net::UnixStream::from_std(socket).unwrap(),
            );
            let _ = p.run_client().await;
        });
        self.lawn_socket = Some(sb.into_std().unwrap());
        Ok(())
    }

    pub fn lawn_socket(&mut self) -> Option<UnixStream> {
        if let Some(s) = self.lawn_socket.take() {
            return Some(s);
        }
        if self.data.kind == LawnSocketKind::Lawn {
            if let Some(s) = self.socket.take() {
                return Some(s);
            }
        }
        None
    }

    pub fn path(&self) -> &OsStr {
        OsStr::from_bytes(&self.data.path)
    }

    pub fn kind(&self) -> LawnSocketKind {
        self.data.kind
    }
}

#[cfg(not(miri))]
#[cfg(test)]
mod tests {
    use super::{LawnSocketDiscoverer, LawnSocketKind};
    use crate::tests::TestInstance;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn socket_from_path() {
        let ti = TestInstance::new(None, None);
        let rt = runtime();
        let discoverer = LawnSocketDiscoverer::new_for_test(ti.config(), rt.handle());
        let socket = discoverer
            .socket_from_path(OsStr::from_bytes(b"/dev/null"))
            .unwrap();
        assert_eq!(socket.path().as_bytes(), b"/dev/null", "expected path");
        assert_eq!(socket.kind(), LawnSocketKind::Lawn, "expected kind");
    }

    #[test]
    fn socket_from_lawn_environment_simple_path() {
        let ti = TestInstance::new(None, None);
        let rt = runtime();
        let discoverer = LawnSocketDiscoverer::new_for_test(ti.config(), rt.handle());
        let socket = discoverer
            .socket_from_lawn_environment(b"v0:s:/dev/null")
            .unwrap();
        assert_eq!(socket.path().as_bytes(), b"/dev/null", "expected path");
        assert_eq!(socket.kind(), LawnSocketKind::Lawn, "expected kind");
    }

    #[test]
    fn socket_from_lawn_environment_cbor() {
        let ti = TestInstance::new(None, None);
        let rt = runtime();
        let discoverer = LawnSocketDiscoverer::new_for_test(ti.config(), rt.handle());
        let socket = discoverer
            .socket_from_lawn_environment(b"v0:c:omJza2RsYXduZHNvY2tJL2Rldi9udWxs")
            .unwrap();
        assert_eq!(
            socket.path().as_bytes(),
            b"/dev/null",
            "expected path for val 1"
        );
        assert_eq!(
            socket.kind(),
            LawnSocketKind::Lawn,
            "expected kind for val 1"
        );
        let socket = discoverer
            .socket_from_lawn_environment(b"v0:c:omJza2Nzc2hkc29ja0wvbm9uZXhpc3RlbnQ")
            .unwrap();
        assert_eq!(
            socket.path().as_bytes(),
            b"/nonexistent",
            "expected path for val 2"
        );
        assert_eq!(
            socket.kind(),
            LawnSocketKind::SSHProxy,
            "expected kind for val 2"
        );
        let socket = discoverer
            .socket_from_lawn_environment(b"v0:c:o2Jza2RsYXduZHNvY2tJL2Rldi9udWxsY2N0eEZhYmMxMjM")
            .unwrap();
        assert_eq!(
            socket.path().as_bytes(),
            b"/dev/null",
            "expected path for val 3"
        );
        assert_eq!(
            socket.kind(),
            LawnSocketKind::Lawn,
            "expected kind for val 3"
        );
        assert_eq!(
            socket.data.context.unwrap().as_ref(),
            b"abc123",
            "expected context for val 3"
        );
        assert!(socket.data.auth.is_none(), "expected auth for val 3");
        assert!(socket.data.username.is_none(), "expected usernam for val 3");
        assert!(socket.data.pass.is_none(), "expected pass for val 3");

        const FULL_DATA: &[u8] = b"v0:c:pmJza2RsYXduZHNvY2tJL2Rldi9udWxsY2N0eEZhYmMxMjNkYXV0aEVQTEFJTmR1c2VyRHVzZXJkcGFzc0RwYXNz";
        // Contains fields we don't yet support.
        assert!(discoverer.socket_from_lawn_environment(FULL_DATA).is_none());

        let socket = discoverer
            .socket_from_lawn_environment_extended(FULL_DATA, true)
            .unwrap();
        assert_eq!(
            socket.path().as_bytes(),
            b"/dev/null",
            "expected path for val 4"
        );
        assert_eq!(
            socket.kind(),
            LawnSocketKind::Lawn,
            "expected kind for val 4"
        );
        assert_eq!(
            socket.data.context.unwrap().as_ref(),
            b"abc123",
            "expected context for val 4"
        );
        assert_eq!(
            socket.data.auth.unwrap().as_ref(),
            b"PLAIN",
            "expected auth for val 4"
        );
        assert_eq!(
            socket.data.username.unwrap().as_ref(),
            b"user",
            "expected usernam for val 4"
        );
        assert_eq!(
            socket.data.pass.unwrap().as_ref(),
            b"pass",
            "expected pass for val 4"
        );
    }
}
