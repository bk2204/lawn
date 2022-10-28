use crate::client::Connection;
use crate::config::Config;
use bytes::Bytes;
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

/// Implements a server-side proxy listener.
pub struct ProxyListener {
    ours: PathBuf,
    agent: UnixListener,
    config: Arc<Config>,
    target: Bytes,
}

impl ProxyListener {
    pub fn new(
        config: Arc<Config>,
        p9p: PathBuf,
        ours: PathBuf,
        target: Bytes,
    ) -> Result<Self, Error> {
        let agent = UnixListener::bind(&p9p)?;
        Ok(ProxyListener {
            ours,
            agent,
            config,
            target,
        })
    }

    pub async fn run_server(&self) -> Result<(), Error> {
        loop {
            let res = self.agent.accept().await;
            if let Ok((conn, _)) = res {
                if let Ok(ours) = UnixStream::connect(&self.ours).await {
                    let config = self.config.clone();
                    let target = self.target.clone();
                    tokio::spawn(async move {
                        let mut p = Proxy::new(config, conn, ours, target);
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
                    let mut p = Proxy::new(config, conn, ours, target);
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
    conn: Connection,
    target: Bytes,
}

impl Proxy {
    pub fn new(config: Arc<Config>, p9p: UnixStream, ours: UnixStream, target: Bytes) -> Proxy {
        let (rd, wr) = p9p.into_split();
        Proxy {
            conn: Connection::new(config, None, ours, false),
            p9p_rd: rd,
            p9p_wr: wr,
            target,
        }
    }

    pub async fn run_server(&mut self) -> Result<(), Error> {
        self.conn.ping().await?;
        self.conn.negotiate_default_version().await?;
        self.conn.auth_external().await?;
        self.conn
            .run_9p(&mut self.p9p_rd, &mut self.p9p_wr, self.target.clone())
            .await?;
        Ok(())
    }
}
