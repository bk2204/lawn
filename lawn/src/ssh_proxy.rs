use crate::config::Config;
use crate::encoding::escape;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::convert::TryInto;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::select;
use tokio::sync::Mutex;

#[derive(Copy, Clone, FromPrimitive, Eq, PartialEq)]
enum MessageKind {
    Failure = 5,
    Success = 6,
    Extension = 27,
    ExtensionFailure = 28,
}

struct SSHMessage {
    len: u32,
    kind: u8,
    data: Vec<u8>,
}

struct Message {
    len: u32,
    id: u32,
    next: u32,
    data: Vec<u8>,
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum Error {
    IOError(io::Error),
    InvalidSize,
    NotSupported,
    NotConnected,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IOError(e)
    }
}

/// Implements a server-side proxy listener.
pub struct ProxyListener {
    ssh: PathBuf,
    ours: PathBuf,
    agent: UnixListener,
    config: Arc<Config>,
}

impl ProxyListener {
    pub fn new(
        config: Arc<Config>,
        ssh: PathBuf,
        ours: PathBuf,
        multiplex: PathBuf,
    ) -> Result<Self, Error> {
        let agent = UnixListener::bind(multiplex)?;
        Ok(ProxyListener {
            ssh,
            ours,
            agent,
            config,
        })
    }

    pub async fn run_server(&self) -> Result<(), Error> {
        loop {
            let res = self.agent.accept().await;
            if let Ok((conn, _)) = res {
                if let Ok(ssh) = UnixStream::connect(&self.ssh).await {
                    if let Ok(ours) = UnixStream::connect(&self.ours).await {
                        let config = self.config.clone();
                        tokio::spawn(async move {
                            let p = Proxy::new(config, Some(ssh), ours, conn);
                            let _ = p.run_server().await;
                        });
                    }
                }
            }
        }
    }
}

pub struct Proxy {
    ssh: Arc<Option<Mutex<UnixStream>>>,
    ours_read: Arc<Mutex<OwnedReadHalf>>,
    ours_write: Arc<Mutex<OwnedWriteHalf>>,
    multiplex: Arc<Mutex<UnixStream>>,
    config: Arc<Config>,
    server_read_timeout: Duration,
}

impl Proxy {
    pub fn new(
        config: Arc<Config>,
        ssh: Option<UnixStream>,
        ours: UnixStream,
        multiplex: UnixStream,
    ) -> Proxy {
        let (rd, wr) = ours.into_split();
        let server_read_timeout = config.proxy_server_read_timeout();
        Proxy {
            config,
            ssh: match ssh {
                Some(ssh) => Arc::new(Some(Mutex::new(ssh))),
                None => Arc::new(None),
            },
            ours_read: Arc::new(Mutex::new(rd)),
            ours_write: Arc::new(Mutex::new(wr)),
            multiplex: Arc::new(Mutex::new(multiplex)),
            server_read_timeout,
        }
    }

    pub async fn client_probe(
        config: Arc<Config>,
        multiplex: std::os::unix::net::UnixStream,
    ) -> Result<std::os::unix::net::UnixStream, Error> {
        let logger = config.logger();
        let sock = Mutex::new(UnixStream::from_std(multiplex).unwrap());
        trace!(logger, "SSH client probe: created socket");
        let m = Self::wrap_message(MessageKind::Extension, None);
        trace!(logger, "SSH client probe: sending message");
        Self::write_ssh_message(&m, &sock).await?;
        trace!(logger, "SSH client probe: reading message");
        let m = Self::read_ssh_message(&sock).await?;
        if m.kind != MessageKind::Success as u8 {
            trace!(
                logger,
                "SSH client probe: message unsuccessful: {:02x}",
                m.kind
            );
            return Err(Error::NotSupported);
        }
        trace!(logger, "SSH client probe: ok");
        Ok(sock.into_inner().into_std().unwrap())
    }

    /// Runs a client to completion.
    ///
    /// A proxy client is a service that runs on the client side of the connection and wraps
    /// messages into the SSH protocol for use on the other side.
    pub async fn run_client(&self) -> Result<(), Error> {
        use tokio::io::AsyncReadExt;
        let mut interval = tokio::time::interval(self.config.proxy_poll_timeout());
        let mut ours_read = self.ours_read.lock().await;
        let logger = self.config.logger();
        let mut buf = vec![0u8; 65536];
        loop {
            select! {
                res = ours_read.read(&mut buf) => {
                    trace!(logger, "proxy client: read: {:?}", res);
                    match res {
                        Ok(n) => {
                            let _ = self.send_client_message(Some(&buf[0..n])).await;
                        },
                        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return Ok(()),
                        Err(e) => return Err(e.into()),
                    }
                }
                _ = interval.tick() => {
                    trace!(logger, "proxy client: tick");
                    let _ = self.send_client_message(None).await;
                }
            }
        }
    }

    async fn send_client_message(&self, msg: Option<&[u8]>) -> Result<(), Error> {
        let logger = self.config.logger();
        let buf = msg.unwrap_or(&[]);
        trace!(
            logger,
            "proxy client: writing extension message with {} bytes of data",
            buf.len()
        );
        self.write_ssh_message_of_type(MessageKind::Extension, buf, &self.multiplex)
            .await?;
        let m = Self::read_ssh_message(&self.multiplex).await?;
        if m.kind == MessageKind::Success as u8 && !m.data.is_empty() {
            let mut sock = self.ours_write.lock().await;
            let _ = sock.write_all(&m.data).await;
        }
        Ok(())
    }

    /// Runs a server to completion.
    ///
    /// A proxy server is a service that runs on the server side of the connection and wraps
    /// messages into the SSH protocol for use on the other side.  This will be implemented as an
    /// SSH agent.
    pub async fn run_server(&self) -> Result<(), Error> {
        loop {
            let res = Self::read_ssh_message(&self.multiplex).await;
            match res {
                Ok(msg) => self.process_server_ssh_message(&msg).await?,
                Err(Error::IOError(e)) if e.kind() == io::ErrorKind::ConnectionReset => {
                    return Ok(())
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn process_server_ssh_message(&self, message: &SSHMessage) -> Result<(), Error> {
        let logger = self.config.logger();
        let ssh = self.ssh.clone();
        let ssh = match ssh.as_ref() {
            Some(ssh) => ssh,
            None => return Err(Error::NotConnected),
        };
        let ours_read = self.ours_read.lock().await;
        trace!(logger, "proxy: parsing SSH message: {:02x}", message.kind);
        match MessageKind::from_u8(message.kind) {
            Some(MessageKind::Extension) => {
                trace!(logger, "proxy: found extension message");
                match self.parse_extension_message(message) {
                    // One of our extension messages with data.
                    Some(Some(ours)) => {
                        trace!(
                            logger,
                            "proxy: found extension message with data: size {:08x}",
                            ours.len(),
                        );
                        let mut ours_write = self.ours_write.lock().await;
                        ours_write.write_all(&ours).await?;
                        trace!(logger, "proxy: relayed message");
                        let mut buf = vec![0u8; 65536];
                        let _ =
                            tokio::time::timeout(self.server_read_timeout, ours_read.readable())
                                .await;
                        match ours_read.try_read(&mut buf) {
                            // We have a message from the server to send.
                            Ok(n) => {
                                let buf = &buf[0..n];
                                trace!(
                                    logger,
                                    "proxy: extension: sending response: {:08x} bytes",
                                    buf.len()
                                );
                                self.write_ssh_message_of_type(
                                    MessageKind::Success,
                                    buf,
                                    &self.multiplex,
                                )
                                .await?;
                            }
                            // No message from the server to send.
                            Err(_) => {
                                trace!(logger, "proxy: extension: sending empty response");
                                let m = Self::wrap_message(MessageKind::Success, None);
                                Self::write_ssh_message(&m, &self.multiplex).await?;
                            }
                        }
                        // TODO: acknowledge
                    }
                    // One of our extension messages without data.  Basically, a ping of sorts to
                    // see if there's any server data.
                    Some(None) => {
                        trace!(logger, "proxy: found extension message without data");
                        let mut buf = vec![0u8; 65536];
                        match ours_read.try_read(&mut buf) {
                            // We have a message from the server to send.
                            Ok(n) => {
                                let buf = &buf[0..n];
                                trace!(
                                    logger,
                                    "proxy: extension: sending response: {:08x} bytes",
                                    buf.len()
                                );
                                self.write_ssh_message_of_type(
                                    MessageKind::Success,
                                    buf,
                                    &self.multiplex,
                                )
                                .await?;
                            }
                            // No message from the server to send.
                            Err(_) => {
                                trace!(logger, "proxy: extension: sending empty response");
                                let m = Self::wrap_message(MessageKind::Success, None);
                                Self::write_ssh_message(&m, &self.multiplex).await?;
                            }
                        }
                    }
                    // Another SSH message.
                    None => {
                        trace!(logger, "proxy: found extension message of unknown type");
                        Self::write_ssh_message(message, ssh).await?;
                        self.proxy_ssh_message(ssh, &self.multiplex).await?;
                    }
                }
            }
            _ => {
                trace!(logger, "proxy: found non-extension message");
                Self::write_ssh_message(message, ssh).await?;
                self.proxy_ssh_message(ssh, &self.multiplex).await?;
            }
        };
        Ok(())
    }

    const EXTENSION: &'static [u8] = b"lawn-v0@ns.crustytoothpaste.net";

    fn wrap_message(kind: MessageKind, msg: Option<&Message>) -> SSHMessage {
        let mut v = Vec::new();
        if kind == MessageKind::Extension {
            let buf = (Self::EXTENSION.len() as u32).to_be_bytes();
            v.extend(&buf);
            v.extend(Self::EXTENSION);
        }
        if let Some(m) = msg {
            let buf = m.len.to_le_bytes();
            v.extend(&buf);
            let buf = m.id.to_le_bytes();
            v.extend(&buf);
            let buf = m.next.to_le_bytes();
            v.extend(&buf);
            v.extend(&m.data);
        };
        SSHMessage {
            len: (v.len() + 1) as u32,
            kind: kind as u8,
            data: v,
        }
    }

    /// Parses an SSH message to see if it's an extension message.
    ///
    /// Returns `Some(Some(mgs))` if the message is for our extension and contains data,
    /// `Some(None)` if it is for our extension and contains no data, and `None` otherwise.
    fn parse_extension_message(&self, message: &SSHMessage) -> Option<Option<Vec<u8>>> {
        let logger = self.config.logger();
        if message.kind == MessageKind::Extension as u8 {
            trace!(logger, "proxy: extension");
            if message.data.len() < 4 {
                return None;
            }
            let slen = u32::from_be_bytes(message.data[0..4].try_into().unwrap());
            trace!(logger, "proxy: extension: string length {:08x}", slen);
            if message.data.len() < (4 + slen) as usize {
                return None;
            }
            trace!(
                logger,
                "proxy: extension: type {}",
                escape(&message.data[4..(4 + slen) as usize])
            );
            if Self::EXTENSION == &message.data[4..(4 + slen) as usize] {
                if message.data.len() == (4 + slen) as usize {
                    Some(None)
                } else {
                    Some(Some(message.data[(4 + slen) as usize..].into()))
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    async fn proxy_ssh_message(
        &self,
        src: &Mutex<UnixStream>,
        dest: &Mutex<UnixStream>,
    ) -> Result<(), Error> {
        let m = Self::read_ssh_message(src).await?;
        Self::write_ssh_message(&m, dest).await?;
        Ok(())
    }

    async fn write_ssh_message_of_type(
        &self,
        kind: MessageKind,
        message: &[u8],
        sock: &Mutex<UnixStream>,
    ) -> Result<(), Error> {
        let mut buf = [0u8; 5 + 4 + Self::EXTENSION.len()];
        let bkind = kind as u8;
        buf[4..5].copy_from_slice(&bkind.to_be_bytes());
        let bufused = match kind {
            MessageKind::Extension => {
                buf[5..9].copy_from_slice(&(Self::EXTENSION.len() as u32).to_be_bytes());
                buf[9..9 + Self::EXTENSION.len()].copy_from_slice(Self::EXTENSION);
                9 + Self::EXTENSION.len()
            }
            _ => 5,
        };
        let len = (bufused - 4 + message.len()) as u32;
        buf[0..4].copy_from_slice(&len.to_be_bytes());
        let buf = &buf[0..bufused];
        let mut ssh = sock.lock().await;
        ssh.write_all(buf).await?;
        ssh.write_all(message).await?;
        Ok(())
    }

    async fn write_ssh_message(
        message: &SSHMessage,
        sock: &Mutex<UnixStream>,
    ) -> Result<(), Error> {
        let mut buf = [0u8; 5];
        buf[0..4].copy_from_slice(&message.len.to_be_bytes());
        buf[4..5].copy_from_slice(&message.kind.to_be_bytes());
        let mut ssh = sock.lock().await;
        ssh.write_all(&buf).await?;
        ssh.write_all(&message.data).await?;
        Ok(())
    }

    async fn read_ssh_message(sock: &Mutex<UnixStream>) -> Result<SSHMessage, Error> {
        use tokio::io::AsyncReadExt;
        let mut ssh = sock.lock().await;
        let mut buf = [0u8; 5];
        ssh.read_exact(&mut buf).await?;
        let len = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        if !(1..((1 << 24) + 12)).contains(&len) {
            return Err(Error::InvalidSize);
        }
        let mut msg = SSHMessage {
            len,
            kind: buf[4],
            data: vec![0u8; (len - 1) as usize],
        };
        ssh.read_exact(&mut msg.data).await?;
        Ok(msg)
    }
}
