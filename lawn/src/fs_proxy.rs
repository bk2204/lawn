use crate::client::Connection;
use crate::config::Config;
use bytes::Bytes;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};

#[derive(Debug)]
pub enum Error {
    IOError(io::Error),
    LawnError(crate::error::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::IOError(e) => write!(f, "{}", e),
            Self::LawnError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IOError(e)
    }
}

impl From<crate::error::Error> for Error {
    fn from(e: crate::error::Error) -> Error {
        Error::LawnError(e)
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum ProxyProtocol {
    P9P,
    SFTP,
}

/// Implements a server-side proxy listener.
pub struct ProxyListener {
    ours: PathBuf,
    agent: UnixListener,
    config: Arc<Config>,
    target: Bytes,
    protocol: ProxyProtocol,
}

impl ProxyListener {
    pub fn new(
        config: Arc<Config>,
        p9p: PathBuf,
        ours: PathBuf,
        target: Bytes,
        protocol: ProxyProtocol,
    ) -> Result<Self, Error> {
        let agent = UnixListener::bind(p9p)?;
        Ok(ProxyListener {
            ours,
            agent,
            config,
            target,
            protocol,
        })
    }

    pub async fn run_server(&self) -> Result<(), Error> {
        loop {
            let res = self.agent.accept().await;
            if let Ok((conn, _)) = res {
                if let Ok(ours) = UnixStream::connect(&self.ours).await {
                    let config = self.config.clone();
                    let target = self.target.clone();
                    let protocol = self.protocol;
                    tokio::spawn(async move {
                        let p = Proxy::new(config, conn, ours, target, protocol);
                        let _ = p.run_server().await;
                    });
                }
            }
        }
    }

    pub async fn run_server_once(&self) -> Result<(), Error> {
        loop {
            let res = self.agent.accept().await;
            if let Ok((conn, _)) = res {
                if let Ok(ours) = UnixStream::connect(&self.ours).await {
                    let config = self.config.clone();
                    let target = self.target.clone();
                    let p = Proxy::new(config, conn, ours, target, self.protocol);
                    let _ = p.run_server().await;
                    return Ok(());
                }
            }
        }
    }
}

pub struct Proxy {
    p9p_rd: OwnedReadHalf,
    p9p_wr: OwnedWriteHalf,
    conn: Arc<Connection>,
    target: Bytes,
    protocol: ProxyProtocol,
}

impl Proxy {
    pub fn new(
        config: Arc<Config>,
        p9p: UnixStream,
        ours: UnixStream,
        target: Bytes,
        protocol: ProxyProtocol,
    ) -> Proxy {
        let (rd, wr) = p9p.into_split();
        Proxy {
            conn: Connection::new(config, None, ours, false),
            p9p_rd: rd,
            p9p_wr: wr,
            target,
            protocol,
        }
    }

    pub fn new_from_connection(
        _config: Arc<Config>,
        p9p: UnixStream,
        conn: Arc<Connection>,
        target: Bytes,
        protocol: ProxyProtocol,
    ) -> Proxy {
        let (rd, wr) = p9p.into_split();
        Proxy {
            conn,
            p9p_rd: rd,
            p9p_wr: wr,
            target,
            protocol,
        }
    }

    pub async fn run_server(self) -> Result<(), Error> {
        self.conn.ping().await?;
        self.conn.negotiate_default_version().await?;
        self.conn.auth_external().await?;
        match self.protocol {
            ProxyProtocol::P9P => {
                self.conn
                    .clone()
                    .run_9p(self.p9p_rd, self.p9p_wr, self.target.clone())
                    .await?
            }
            ProxyProtocol::SFTP => {
                self.conn
                    .clone()
                    .run_sftp(self.p9p_rd, self.p9p_wr, self.target.clone())
                    .await?
            }
        };
        Ok(())
    }
}
