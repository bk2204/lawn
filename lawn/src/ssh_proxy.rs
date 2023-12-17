use crate::config::Config;
use crate::encoding::escape;
use async_trait::async_trait;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::convert::TryInto;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::Mutex;

#[derive(Copy, Clone, FromPrimitive, Eq, PartialEq)]
enum MessageKind {
    Failure = 5,
    Success = 6,
    Extension = 27,
    ExtensionFailure = 28,
}

// Based on the Rust standard library.
#[inline]
fn advance_slices(bufs: &[io::IoSlice<'_>], n: usize) -> (usize, usize) {
    // Number of buffers to remove.
    let mut remove = 0;
    // Remaining length before reaching n. This prevents overflow
    // that could happen if the length of slices in `bufs` were instead
    // accumulated. Those slice may be aliased and, if they are large
    // enough, their added length may overflow a `usize`.
    let mut left = n;
    for buf in bufs.iter() {
        if let Some(remainder) = left.checked_sub(buf.len()) {
            left = remainder;
            remove += 1;
        } else {
            break;
        }
    }

    (remove, left)
}

async fn write_full<W: AsyncWriteExt + Unpin + Send>(data: &[&[u8]], w: &mut W) -> io::Result<()> {
    let mut len: usize = data.iter().map(|x| x.len()).sum();
    let mut slices: Vec<io::IoSlice<'_>> = data.iter().map(|item| io::IoSlice::new(item)).collect();
    let mut total_remove = 0;
    while len > 0 {
        let nwritten = w.write_vectored(&slices[total_remove..]).await?;
        len -= nwritten;
        if len == 0 {
            break;
        }
        let (remove, left) = advance_slices(&slices[total_remove..], nwritten);
        total_remove += remove;
        slices[0] = io::IoSlice::new(&data[total_remove][left..]);
    }
    Ok(())
}

#[async_trait]
trait Writable {
    async fn write_full<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> io::Result<()>;
}

struct SSHMessage {
    len: u32,
    kind: u8,
    data: Vec<u8>,
}

#[async_trait]
impl Writable for SSHMessage {
    async fn write_full<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> io::Result<()> {
        let lenbuf = self.len.to_be_bytes();
        let data = [&lenbuf, std::slice::from_ref(&self.kind), &self.data];
        write_full(&data, w).await
    }
}

struct BorrowedSSHMessage<'a> {
    len: u32,
    kind: u8,
    data: &'a [u8],
}

#[async_trait]
impl<'a> Writable for BorrowedSSHMessage<'a> {
    async fn write_full<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> io::Result<()> {
        let lenbuf = self.len.to_be_bytes();
        let data = [&lenbuf, std::slice::from_ref(&self.kind), &self.data];
        write_full(&data, w).await
    }
}

struct Message {
    len: u32,
    id: u32,
    next: u32,
    data: Vec<u8>,
}

#[async_trait]
impl Writable for Message {
    async fn write_full<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> io::Result<()> {
        let lenbuf = self.len.to_be_bytes();
        let idbuf = self.id.to_be_bytes();
        let nextbuf = self.next.to_be_bytes();
        let data: &[&[u8]] = &[&lenbuf, &idbuf, &nextbuf, &self.data];
        write_full(&data, w).await
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum Error {
    IOError(io::Error),
    InvalidSize,
    NotSupported,
    NotConnected,
    Unnotifiable,
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

#[allow(clippy::upper_case_acronyms)]
enum ResponseType {
    Lawn,
    LawnPing,
    SSH(oneshot::Receiver<SSHMessage>),
}

impl PartialEq for ResponseType {
    fn eq(&self, other: &ResponseType) -> bool {
        matches!(
            (self, other),
            (ResponseType::Lawn, ResponseType::Lawn)
                | (ResponseType::LawnPing, ResponseType::LawnPing)
                | (ResponseType::SSH(_), ResponseType::SSH(_))
        )
    }
}

pub struct Proxy {
    ssh_read: Arc<Option<Mutex<OwnedReadHalf>>>,
    ssh_write: Arc<Option<Mutex<OwnedWriteHalf>>>,
    ours_read: Arc<Mutex<OwnedReadHalf>>,
    ours_write: Arc<Mutex<OwnedWriteHalf>>,
    multiplex_read: Arc<Mutex<OwnedReadHalf>>,
    multiplex_write: Arc<Mutex<OwnedWriteHalf>>,
    config: Arc<Config>,
    server_read_timeout: Duration,
    lawn_entries: AtomicUsize,
    ssh_entries: AtomicUsize,
}

impl Proxy {
    const CAPACITY: usize = 128;

    pub fn new(
        config: Arc<Config>,
        ssh: Option<UnixStream>,
        ours: UnixStream,
        multiplex: UnixStream,
    ) -> Arc<Proxy> {
        let (rd, wr) = ours.into_split();
        let (mrd, mwr) = multiplex.into_split();
        let (sshrd, sshwr) = match ssh {
            Some(stream) => {
                let (sshrd, sshwr) = stream.into_split();
                (
                    Arc::new(Some(Mutex::new(sshrd))),
                    Arc::new(Some(Mutex::new(sshwr))),
                )
            }
            None => (Arc::new(None), Arc::new(None)),
        };
        let server_read_timeout = config.proxy_server_read_timeout();
        Arc::new(Proxy {
            config,
            ssh_read: sshrd,
            ssh_write: sshwr,
            ours_read: Arc::new(Mutex::new(rd)),
            ours_write: Arc::new(Mutex::new(wr)),
            multiplex_read: Arc::new(Mutex::new(mrd)),
            multiplex_write: Arc::new(Mutex::new(mwr)),
            server_read_timeout,
            lawn_entries: AtomicUsize::new(0),
            ssh_entries: AtomicUsize::new(0),
        })
    }

    pub async fn client_probe(
        config: Arc<Config>,
        multiplex: std::os::unix::net::UnixStream,
    ) -> Result<std::os::unix::net::UnixStream, Error> {
        let logger = config.logger();
        let _ = multiplex.set_nonblocking(true);
        let sock = UnixStream::from_std(multiplex).unwrap();
        let (mrd, mwr) = sock.into_split();
        let mwr = Mutex::new(mwr);
        let mrd = Mutex::new(mrd);
        trace!(logger, "SSH client probe: created socket");
        let m = Self::wrap_message(MessageKind::Extension, None);
        trace!(logger, "SSH client probe: sending message");
        Self::write_ssh_message(&m, &mwr).await?;
        trace!(logger, "SSH client probe: reading message");
        let m = Self::read_ssh_message(&mrd).await?;
        if m.kind != MessageKind::Success as u8 {
            trace!(
                logger,
                "SSH client probe: message unsuccessful: {:02x}",
                m.kind
            );
            return Err(Error::NotSupported);
        }
        trace!(logger, "SSH client probe: ok");
        let mrd = mrd.into_inner();
        let mwr = mwr.into_inner();
        let std = mrd.reunite(mwr).unwrap().into_std().unwrap();
        let _ = std.set_nonblocking(false);
        Ok(std)
    }

    /// Runs a client to completion.
    ///
    /// A proxy client is a service that runs on the client side of the connection and wraps
    /// messages into the SSH protocol for use on the other side.
    pub async fn run_client(self: Arc<Self>) -> Result<(), Error> {
        let mut buf = vec![0u8; 65536];
        let logger = self.config.logger();
        let timeout = self.config.proxy_poll_timeout();
        let this = self.clone();
        tokio::spawn(async move {
            let logger = this.config.logger();
            let mut multiplex_read = this.multiplex_read.lock().await;
            let mut sock = this.ours_write.lock().await;
            loop {
                let m = match Self::read_ssh_message_unlocked(&mut *multiplex_read).await {
                    Ok(m) => {
                        trace!(
                            logger,
                            "proxy client: read ssh: {:?} bytes; message {:02x}",
                            m.len,
                            m.kind
                        );
                        m
                    }
                    Err(e) => {
                        trace!(logger, "proxy client: read ssh: error: {:?}", e);
                        return;
                    }
                };
                if m.kind == MessageKind::Success as u8 && !m.data.is_empty() {
                    let _ = sock.write_all(&m.data).await;
                }
            }
        });
        loop {
            let ours_read = self.ours_read.lock().await;
            let res = tokio::time::timeout(timeout, ours_read.readable()).await;
            match res {
                Ok(Ok(())) => {
                    let res = ours_read.try_read(&mut buf);
                    trace!(logger, "proxy client: read ours: {:?}", res);
                    match res {
                        Ok(0) => {
                            trace!(logger, "proxy client: read ours: EOF");
                            return Ok(());
                        }
                        Ok(n) => {
                            let _ = self.send_client_message(Some(&buf[0..n])).await;
                        }
                        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                            return Ok(());
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            let _ = self.send_client_message(None).await;
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                    }
                }
                Ok(Err(e)) => {
                    trace!(logger, "proxy client: error polling for reading: {}", e);
                }
                Err(_) => {
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
        self.write_ssh_message_of_type(MessageKind::Extension, buf, &self.multiplex_write)
            .await?;
        Ok(())
    }

    /// Runs a server to completion.
    ///
    /// A proxy server is a service that runs on the server side of the connection and wraps
    /// messages into the SSH protocol for use on the other side.  This will be implemented as an
    /// SSH agent.
    pub async fn run_server(self: Arc<Self>) -> Result<(), Error> {
        let (tx, rx) = mpsc::channel(Self::CAPACITY);
        let ssh = self.ssh_read.clone();
        let logger = self.config.logger();
        tokio::spawn(async move {
            if let Err(e) = Self::read_ssh_socket(ssh, rx).await {
                error!(logger, "error reading SSH socket: {:?}", e);
            }
        });
        let logger = self.config.logger();
        let (mdtx, mdrx) = mpsc::channel(Self::CAPACITY);
        let this = self.clone();
        tokio::spawn(async move {
            if let Err(e) = this.reply_to_proxy(mdrx).await {
                if let Error::IOError(e) = e {
                    if e.kind() != io::ErrorKind::BrokenPipe {
                        error!(logger, "error replying to messages: {:?}", e);
                    }
                } else {
                    error!(logger, "error replying to messages: {:?}", e);
                }
            }
        });
        loop {
            let res = Self::read_ssh_message(&self.multiplex_read).await;
            match res {
                Ok(msg) => {
                    self.process_server_ssh_message(&msg, tx.clone(), mdtx.clone())
                        .await?
                }
                Err(Error::IOError(e)) if e.kind() == io::ErrorKind::ConnectionReset => {
                    return Ok(())
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn reply_to_proxy(
        self: Arc<Self>,
        mdrx: mpsc::Receiver<ResponseType>,
    ) -> Result<(), Error> {
        let mut mdrx = mdrx;
        let logger = self.config.logger();
        let mut buf = vec![0u8; 65536];
        let ours_read = self.ours_read.lock().await;
        while let Some(item) = mdrx.recv().await {
            let (item, count) = {
                if let ResponseType::Lawn = &item {
                    let entries = self.lawn_entries.fetch_sub(1, Ordering::AcqRel);
                    (item, entries)
                } else {
                    (item, 0)
                }
            };
            match item {
                ResponseType::Lawn | ResponseType::LawnPing => {
                    if count == 0 && item == ResponseType::Lawn {
                        // There's no other Lawn message in the queue.  Let's wait a bit to see if one
                        // comes in.
                        let _ =
                            tokio::time::timeout(self.server_read_timeout, ours_read.readable())
                                .await;
                    } else {
                        // There's other Lawn messages in the queue, so we should simply attempt to read
                        // now and if there's nothing, send an immediate response.  A future message will
                        // handle proxying any leftovers.
                    }
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
                                &self.multiplex_write,
                            )
                            .await?;
                        }
                        // No message from the server to send.
                        Err(_) => {
                            trace!(logger, "proxy: extension: sending empty response");
                            let m = Self::wrap_message(MessageKind::Success, None);
                            Self::write_ssh_message(&m, &self.multiplex_write).await?;
                        }
                    }
                }
                ResponseType::SSH(chan) => {
                    let data = match chan.await {
                        Ok(data) => data,
                        Err(e) => {
                            trace!(logger, "proxy: ssh: error reading SSH channel: {}", e);
                            return Err(Error::Unnotifiable);
                        }
                    };
                    Self::write_ssh_message(&data, &self.multiplex_write).await?;
                }
            };
        }
        Ok(())
    }

    async fn read_ssh_socket(
        ssh: Arc<Option<Mutex<OwnedReadHalf>>>,
        rx: mpsc::Receiver<oneshot::Sender<SSHMessage>>,
    ) -> Result<(), Error> {
        let mut rx = rx;
        let ssh = match ssh.as_ref() {
            Some(ssh) => ssh,
            None => return Err(Error::NotConnected),
        };
        let mut ssh = ssh.lock().await;
        while let Some(chan) = rx.recv().await {
            let m = Self::read_ssh_message_unlocked(&mut *ssh).await?;
            let _ = chan.send(m);
        }
        Ok(())
    }

    async fn process_server_ssh_message(
        &self,
        message: &SSHMessage,
        chan: mpsc::Sender<oneshot::Sender<SSHMessage>>,
        mdchan: mpsc::Sender<ResponseType>,
    ) -> Result<(), Error> {
        let logger = self.config.logger();
        let sshwr = self.ssh_write.clone();
        let sshwr = match sshwr.as_ref() {
            Some(ssh) => ssh,
            None => return Err(Error::NotConnected),
        };
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
                        self.lawn_entries.fetch_add(1, Ordering::AcqRel);
                        let _ = mdchan.send(ResponseType::Lawn).await;
                    }
                    // One of our extension messages without data.  Basically, a ping of sorts to
                    // see if there's any server data.
                    Some(None) => {
                        trace!(logger, "proxy: found extension message without data");
                        self.lawn_entries.fetch_add(1, Ordering::AcqRel);
                        let _ = mdchan.send(ResponseType::LawnPing).await;
                    }
                    // Another SSH message.
                    None => {
                        trace!(logger, "proxy: found extension message of unknown type");
                        let (tx, rx) = oneshot::channel();
                        let _ = chan.send(tx).await;
                        Self::write_ssh_message_with_closure(message, sshwr, async {
                            let _ = mdchan.send(ResponseType::SSH(rx)).await;
                            self.ssh_entries.fetch_add(1, Ordering::AcqRel);
                        })
                        .await?;
                    }
                }
            }
            _ => {
                trace!(logger, "proxy: found non-extension message");
                let (tx, rx) = oneshot::channel();
                let _ = chan.send(tx).await;
                Self::write_ssh_message_with_closure(message, sshwr, async {
                    let _ = mdchan.send(ResponseType::SSH(rx)).await;
                    self.ssh_entries.fetch_add(1, Ordering::AcqRel);
                })
                .await?;
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

    async fn write_ssh_message_of_type(
        &self,
        kind: MessageKind,
        message: &[u8],
        sock: &Mutex<OwnedWriteHalf>,
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
        sock: &Mutex<OwnedWriteHalf>,
    ) -> Result<(), Error> {
        let mut ssh = sock.lock().await;
        message.write_full(&mut *ssh).await?;
        Ok(())
    }

    async fn write_ssh_message_with_closure<F: std::future::Future<Output = ()>>(
        message: &SSHMessage,
        sock: &Mutex<OwnedWriteHalf>,
        f: F,
    ) -> Result<(), Error> {
        let mut ssh = sock.lock().await;
        message.write_full(&mut *ssh).await?;
        f.await;
        Ok(())
    }

    async fn read_ssh_message<T: AsyncReadExt + Unpin>(
        sock: &Mutex<T>,
    ) -> Result<SSHMessage, Error> {
        let mut ssh = sock.lock().await;
        Self::read_ssh_message_unlocked(&mut *ssh).await
    }

    async fn read_ssh_message_unlocked<T: AsyncReadExt + Unpin>(
        ssh: &mut T,
    ) -> Result<SSHMessage, Error> {
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

    async fn read_borrowed_ssh_message<'a>(
        sock: &Mutex<UnixStream>,
        v: &'a mut Vec<u8>,
    ) -> Result<BorrowedSSHMessage<'a>, Error> {
        let mut ssh = sock.lock().await;
        let mut buf = [0u8; 5];
        ssh.read_exact(&mut buf).await?;
        let len = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        if !(1..((1 << 24) + 12)).contains(&len) {
            return Err(Error::InvalidSize);
        }
        let datalen = (len - 1) as usize;
        v.clear();
        if v.capacity() < datalen {
            v.reserve(datalen - v.capacity());
        }
        {
            let slice = unsafe {
                std::mem::transmute::<_, &mut [u8]>(&mut v.spare_capacity_mut()[0..datalen])
            };
            ssh.read_exact(slice).await?;
            unsafe { v.set_len(datalen) };
        }
        let msg = BorrowedSSHMessage {
            len,
            kind: buf[4],
            data: &v[0..datalen],
        };
        Ok(msg)
    }
}
