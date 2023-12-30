use crate::config::Config;
use crate::error::{Error, ErrorKind};
use crate::ssh_proxy;
use lawn_constants::logger::AsLogStr;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use tokio::runtime::Handle;

#[derive(PartialEq, Eq, Copy, Clone, Debug, Hash)]
pub enum LawnSocketKind {
    Lawn,
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

pub struct LawnSocketDiscoverer<'a> {
    config: Arc<Config>,
    handle: &'a Handle,
}

impl<'a> LawnSocketDiscoverer<'a> {
    pub fn new(config: Arc<Config>, handle: &'a Handle) -> Self {
        Self { config, handle }
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

    pub fn autodiscover(&self, prune: bool) -> Option<LawnSocket> {
        let logger = self.config.logger();
        debug!(logger, "performing socket autodiscovery");
        let senv = self.config.template_context(None, None).senv.unwrap();
        if let Some(path) = senv.get(b"SSH_AUTH_SOCK" as &[u8]) {
            debug!(logger, "trying SSH socket {}", path.as_ref().as_log_str());
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
                        Ok(sock) => {
                            return Some(LawnSocket {
                                kind: LawnSocketKind::SSHProxy,
                                config: self.config.clone(),
                                socket: Some(sock),
                                lawn_socket: None,
                                path: path.to_owned(),
                            });
                        }
                        Err(_) => {
                            debug!(logger, "failed to connect to SSH socket");
                        }
                    }
                }
                Err(e) => {
                    debug!(logger, "SSH socket: failed to connect: {}", e);
                }
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
                            path: p.as_os_str().to_owned(),
                            kind: LawnSocketKind::Lawn,
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
        match UnixStream::connect(path) {
            Ok(sock) => Some(LawnSocket {
                path: path.to_owned(),
                kind,
                socket: Some(sock),
                config: self.config.clone(),
                lawn_socket: None,
            }),
            Err(_) => None,
        }
    }
}

pub struct LawnSocket {
    path: OsString,
    kind: LawnSocketKind,
    socket: Option<UnixStream>,
    config: Arc<Config>,
    lawn_socket: Option<UnixStream>,
}

impl LawnSocket {
    pub fn spawn_proxies(&mut self, handle: &Handle) -> Result<(), Error> {
        if self.kind != LawnSocketKind::SSHProxy {
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
        if self.kind == LawnSocketKind::Lawn {
            if let Some(s) = self.socket.take() {
                return Some(s);
            }
        }
        None
    }

    pub fn path(&self) -> &OsStr {
        &self.path
    }

    pub fn kind(&self) -> LawnSocketKind {
        self.kind
    }
}
