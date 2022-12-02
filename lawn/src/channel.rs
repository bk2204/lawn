#![allow(dead_code)]

use crate::config::Logger;
use crate::task::block_on_async;
use crate::unix;
use bytes::Bytes;
use lawn_9p::auth::{AuthenticationInfo, Authenticator};
use lawn_9p::backend::libc::LibcBackend;
use lawn_9p::backend::ToIdentifier;
use lawn_9p::server::Server as Server9P;
use lawn_constants::error::Error as Errno;
use lawn_protocol::protocol;
use lawn_protocol::protocol::{ChannelID, ClipboardChannelOperation, ErrorBody, ResponseCode};
use std::collections::HashMap;
use std::io;
use std::os::raw::c_int;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::sync;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio_pipe::{PipeRead, PipeWrite};

pub struct ChannelManager {
    map: RwLock<HashMap<ChannelID, Arc<dyn Channel + Send + Sync>>>,
    id: Mutex<u32>,
    notifier: tokio::sync::Mutex<Option<Sender<ChannelID>>>,
}

impl ChannelManager {
    pub fn new(notifier: Option<Sender<ChannelID>>) -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            id: Mutex::new(0),
            notifier: tokio::sync::Mutex::new(notifier),
        }
    }

    pub fn next_id(&self) -> ChannelID {
        let mut g = self.id.lock().unwrap();
        let val = *g;
        *g += 1;
        ChannelID(val)
    }

    pub fn contains(&self, id: ChannelID) -> bool {
        let g = self.map.read().unwrap();
        g.contains_key(&id)
    }

    pub fn insert(&self, id: ChannelID, ch: Arc<dyn Channel + Send + Sync>) {
        let mut g = self.map.write().unwrap();
        g.insert(id, ch);
    }

    pub fn remove(&self, id: ChannelID) -> Option<Arc<dyn Channel + Send + Sync>> {
        let mut g = self.map.write().unwrap();
        g.remove(&id)
    }

    pub fn get(&self, id: ChannelID) -> Option<Arc<dyn Channel + Send + Sync>> {
        let g = self.map.read().unwrap();
        g.get(&id).map(Arc::clone)
    }

    pub async fn ping_channels(&self) {
        {
            let g = self.notifier.lock().await;
            if g.is_none() {
                return;
            }
        }
        let channels: Vec<Arc<dyn Channel + Send + Sync>> = {
            let g = self.map.read().unwrap();
            g.values().cloned().collect()
        };
        for ch in channels {
            match ch.ping() {
                Ok(()) => (),
                Err(protocol::Error {
                    code: ResponseCode::NotSupported,
                    ..
                }) => (),
                Err(protocol::Error {
                    code: ResponseCode::Gone,
                    ..
                }) => {
                    let sender = self.notifier.lock().await;
                    let _ = sender.as_ref().unwrap().send(ch.id()).await;
                }
                // TODO: maybe do something different here?
                Err(_) => (),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn poll(
    logger: Arc<Logger>,
    selectors: Vec<u32>,
    flags: Option<Vec<u64>>,
    fds: Vec<RawFd>,
    id: ChannelID,
    duration: Duration,
    alive: bool,
    ch: oneshot::Sender<Result<Vec<protocol::PollChannelFlags>, protocol::Error>>,
) {
    let base_flags = protocol::PollChannelFlags::default();
    block_on_async(async move {
        if selectors.len() > 3 {
            ch.send(Err(protocol::Error {
                code: ResponseCode::InvalidParameters,
                body: None,
            }))
            .unwrap();
            return;
        }
        if duration > Duration::from_millis(30 * 1000) {
            ch.send(Err(protocol::Error {
                code: ResponseCode::InvalidParameters,
                body: None,
            }))
            .unwrap();
            return;
        }
        trace!(
            logger,
            "channel {}: poll: polling {:?} for {:?}",
            id,
            selectors,
            duration
        );
        let mut pfd = Vec::with_capacity(selectors.len());
        let flags = match flags {
            Some(flags) if flags.len() == selectors.len() => {
                let r: Result<Vec<_>, _> = flags
                    .iter()
                    .map(|f| {
                        let flags =
                            protocol::PollChannelFlags::from_bits(*f).ok_or(protocol::Error {
                                code: ResponseCode::InvalidParameters,
                                body: None,
                            })?;
                        let mut result = 0;
                        if flags.contains(protocol::PollChannelFlags::Input) {
                            result |= libc::POLLIN;
                        }
                        if flags.contains(protocol::PollChannelFlags::Output) {
                            result |= libc::POLLOUT;
                        }
                        if flags.contains(protocol::PollChannelFlags::Hangup) {
                            result |= libc::POLLHUP;
                        }
                        Ok(result)
                    })
                    .collect();
                r
            }
            None => Ok((0..(selectors.len()))
                .map(|_| libc::POLLIN | libc::POLLOUT | libc::POLLHUP)
                .collect()),
            _ => Err(protocol::Error {
                code: ResponseCode::InvalidParameters,
                body: None,
            }),
        };
        let flags = match flags {
            Ok(flags) => flags,
            Err(_) => {
                ch.send(Err(protocol::Error {
                    code: ResponseCode::InvalidParameters,
                    body: None,
                }))
                .unwrap();
                return;
            }
        };
        for (fd, events) in fds.iter().zip(flags.iter()) {
            pfd.push(libc::pollfd {
                fd: *fd,
                events: *events,
                revents: 0,
            });
        }
        trace!(logger, "channel {}: poll: starting blocking task", id);
        tokio::task::spawn_blocking(move || {
            let pfd: &mut [libc::pollfd] = &mut pfd;
            trace!(logger, "channel {}: poll: starting poll(2)", id);
            let res = unix::call_with_result(|| unsafe {
                libc::poll(
                    pfd.as_mut_ptr(),
                    pfd.len() as libc::nfds_t,
                    duration.as_millis() as c_int,
                )
            });
            trace!(
                logger,
                "channel {}: poll: finished poll(2): {:?} ready",
                id,
                res
            );
            let msg = match res {
                Ok(_) => {
                    let mut v = Vec::with_capacity(selectors.len());
                    vec![base_flags; selectors.len()];
                    for fd in pfd {
                        let mut flags = base_flags;
                        if (fd.revents & libc::POLLIN) != 0 {
                            flags |= protocol::PollChannelFlags::Input;
                        }
                        if (fd.revents & libc::POLLOUT) != 0 {
                            flags |= protocol::PollChannelFlags::Output;
                        }
                        if (fd.revents & libc::POLLHUP) != 0 {
                            flags |= protocol::PollChannelFlags::Hangup;
                        }
                        if (fd.revents & libc::POLLERR) != 0 {
                            flags |= protocol::PollChannelFlags::Error;
                        }
                        if (fd.revents & libc::POLLNVAL) != 0 {
                            flags |= protocol::PollChannelFlags::Invalid;
                        }
                        if !alive {
                            flags |= protocol::PollChannelFlags::Gone;
                        }
                        trace!(
                            logger,
                            "channel {}: poll: fd {}: flags {}",
                            id,
                            fd.fd,
                            flags.bits()
                        );
                        v.push(flags);
                    }
                    Ok(v)
                }
                Err(e) => Err(e.into()),
            };
            let _ = ch.send(msg);
        });
    })
}

pub trait Channel {
    fn id(&self) -> ChannelID;
    fn read(&self, selector: u32) -> Result<Bytes, protocol::Error>;
    fn write(&self, selector: u32, data: Bytes) -> Result<u64, protocol::Error>;
    fn poll(
        &self,
        selectors: Vec<u32>,
        flags: Option<Vec<u64>>,
        delay: Duration,
        ch: oneshot::Sender<Result<Vec<protocol::PollChannelFlags>, protocol::Error>>,
    );
    fn ping(&self) -> Result<(), protocol::Error>;
    fn detach_selector(&self, selector: u32) -> Result<(), protocol::Error>;
    fn is_alive(&self) -> bool;
    fn set_dead(&self);
}

type OptionLocked<T> = Option<Arc<sync::Mutex<T>>>;
type OptionLockedWrite = OptionLocked<PipeWrite>;
type OptionLockedRead = OptionLocked<PipeRead>;

pub struct ServerGenericCommandChannel {
    // TODO: take the FDs out of the child and handle them individually
    cmd: Mutex<Child>,
    fds: Arc<sync::RwLock<(OptionLockedWrite, OptionLockedRead, OptionLockedRead)>>,
    exit_status: Mutex<Option<ExitStatus>>,
    id: ChannelID,
    logger: Arc<Logger>,
    alive: AtomicBool,
}

pub struct ServerCommandChannel {
    ch: ServerGenericCommandChannel,
}

impl ServerGenericCommandChannel {
    fn fd_from_selector(&self, selector: u32) -> Option<i32> {
        let fds = self.fds.clone();
        block_on_async(async move {
            let g = fds.read().await;
            match selector {
                0 => match &g.0 {
                    Some(f) => Some(f.lock().await.as_raw_fd()),
                    None => None,
                },
                1 => match &g.1 {
                    Some(f) => Some(f.lock().await.as_raw_fd()),
                    None => None,
                },
                2 => match &g.2 {
                    Some(f) => Some(f.lock().await.as_raw_fd()),
                    None => None,
                },
                _ => None,
            }
        })
    }

    // TODO: use native implementation on 1.58.1 or newer.
    fn convert_exit(e: ExitStatus) -> i32 {
        if let Some(sig) = e.signal() {
            return sig;
        }
        if let Some(code) = e.code() {
            return code << 8;
        }
        -1
    }
}

impl ServerCommandChannel {
    pub fn new(
        logger: Arc<Logger>,
        id: ChannelID,
        cmd: Command,
    ) -> Result<ServerCommandChannel, protocol::Error> {
        let mut cmd = cmd;
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        trace!(logger, "channel {}: spawn {:?}", id, cmd);
        let cmd = match cmd.spawn() {
            Ok(cmd) => cmd,
            Err(e) => return Err(e.into()),
        };
        trace!(logger, "channel {}: spawn ok: pid {}", id, cmd.id());
        let fds = (
            Some(Arc::new(sync::Mutex::new(unsafe {
                PipeWrite::from_raw_fd(cmd.stdin.as_ref().unwrap().as_raw_fd())
            }))),
            Some(Arc::new(sync::Mutex::new(unsafe {
                PipeRead::from_raw_fd(cmd.stdout.as_ref().unwrap().as_raw_fd())
            }))),
            Some(Arc::new(sync::Mutex::new(unsafe {
                PipeRead::from_raw_fd(cmd.stderr.as_ref().unwrap().as_raw_fd())
            }))),
        );
        Ok(ServerCommandChannel {
            ch: ServerGenericCommandChannel {
                cmd: Mutex::new(cmd),
                fds: Arc::new(sync::RwLock::new(fds)),
                exit_status: Mutex::new(None),
                id,
                logger,
                alive: AtomicBool::new(true),
            },
        })
    }
}

impl Channel for ServerCommandChannel {
    fn id(&self) -> ChannelID {
        self.ch.id()
    }

    fn read(&self, selector: u32) -> Result<Bytes, protocol::Error> {
        self.ch.read(selector)
    }

    fn write(&self, selector: u32, data: Bytes) -> Result<u64, protocol::Error> {
        self.ch.write(selector, data)
    }

    fn poll(
        &self,
        selectors: Vec<u32>,
        flags: Option<Vec<u64>>,
        duration: Duration,
        ch: oneshot::Sender<Result<Vec<protocol::PollChannelFlags>, protocol::Error>>,
    ) {
        self.ch.poll(selectors, flags, duration, ch)
    }

    fn ping(&self) -> Result<(), protocol::Error> {
        self.ch.ping()
    }

    fn detach_selector(&self, selector: u32) -> Result<(), protocol::Error> {
        self.ch.detach_selector(selector)
    }

    fn is_alive(&self) -> bool {
        self.ch.is_alive()
    }

    fn set_dead(&self) {
        self.ch.set_dead()
    }
}

impl Channel for ServerGenericCommandChannel {
    fn id(&self) -> ChannelID {
        self.id
    }

    fn read(&self, selector: u32) -> Result<Bytes, protocol::Error> {
        let fds = self.fds.clone();
        let id = self.id;
        let logger = self.logger.clone();
        block_on_async(async move {
            let io = {
                let g = fds.read().await;
                let io = match selector {
                    1 => &g.1,
                    2 => &g.2,
                    _ => return Err(protocol::Error::from_errno(libc::EBADF)),
                };
                match io {
                    Some(io) => io.clone(),
                    None => return Err(protocol::Error::from_errno(libc::EBADF)),
                }
            };
            let mut v = vec![0u8; 4096];
            let mut g = io.lock().await;
            let res = g.read(&mut v).await;
            trace!(logger, "channel {}: read: {:?}", id, res);
            match res {
                Ok(n) => {
                    v.truncate(n);
                    Ok(v.into())
                }
                Err(e) => Err(e.into()),
            }
        })
    }

    fn write(&self, selector: u32, data: Bytes) -> Result<u64, protocol::Error> {
        let fds = self.fds.clone();
        let id = self.id;
        let logger = self.logger.clone();
        block_on_async(async move {
            let io = {
                let g = fds.read().await;
                let io = match selector {
                    0 => &g.0,
                    _ => return Err(protocol::Error::from_errno(libc::EBADF)),
                };
                match io {
                    Some(io) => io.clone(),
                    None => return Err(protocol::Error::from_errno(libc::EBADF)),
                }
            };
            let mut g = io.lock().await;
            trace!(logger, "channel {}: write", id);
            let res = g.write(&data).await;
            trace!(logger, "channel {}: write: {:?}", id, res);
            match res {
                Ok(n) => Ok(n as u64),
                Err(e) => Err(e.into()),
            }
        })
    }

    fn poll(
        &self,
        selectors: Vec<u32>,
        flags: Option<Vec<u64>>,
        duration: Duration,
        ch: oneshot::Sender<Result<Vec<protocol::PollChannelFlags>, protocol::Error>>,
    ) {
        let logger = self.logger.clone();
        let base_flags = protocol::PollChannelFlags::default();
        //let base_flags: protocol::PollChannelFlags = match self.ping() {
        //    Ok(()) => Default::default(),
        //    Err(protocol::Error{ code: ResponseCode::Gone, ..}) => protocol::PollChannelFlags::Gone,
        //    Err(e) => {
        //        ch.send(Err(e)).unwrap();
        //        return;
        //    }
        //};
        trace!(logger, "channel {}: poll: flags {:?}", self.id, base_flags);
        let id = self.id;
        let fds: Result<Vec<_>, protocol::Error> = selectors
            .iter()
            .map(|s| {
                self.fd_from_selector(*s).ok_or(protocol::Error {
                    code: ResponseCode::InvalidParameters,
                    body: None,
                })
            })
            .collect();
        match fds {
            Ok(fds) => poll(
                logger,
                selectors,
                flags,
                fds,
                id,
                duration,
                self.is_alive(),
                ch,
            ),
            Err(e) => {
                let _ = ch.send(Err(e));
            }
        }
    }

    fn ping(&self) -> Result<(), protocol::Error> {
        {
            let g = self.exit_status.lock().unwrap();
            if let Some(st) = *g {
                return Err(protocol::Error {
                    code: ResponseCode::Gone,
                    body: Some(ErrorBody::Exit(Self::convert_exit(st))),
                });
            }
        }
        let mut g = self.cmd.lock().unwrap();
        match g.try_wait() {
            Ok(Some(st)) => {
                let mut g = self.exit_status.lock().unwrap();
                *g = Some(st);
                Err(protocol::Error {
                    code: ResponseCode::Gone,
                    body: Some(ErrorBody::Exit(Self::convert_exit(st))),
                })
            }
            Ok(None) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn detach_selector(&self, selector: u32) -> Result<(), protocol::Error> {
        let fds = self.fds.clone();
        block_on_async(async move {
            let mut g = fds.write().await;
            match selector {
                0 => {
                    if g.0.is_some() {
                        let fp = g.0.take().unwrap();
                        let r = block_on_async(async move {
                            let mut g = fp.lock().await;
                            g.flush().await
                        });
                        g.0 = None;
                        return r.map_err(|e| e.into());
                    }
                }
                1 => {
                    if g.1.is_some() {
                        g.1 = None;
                        return Ok(());
                    }
                }
                2 => {
                    if g.2.is_some() {
                        g.2 = None;
                        return Ok(());
                    }
                }
                _ => return Err(protocol::Error::from_errno(libc::EBADF)),
            };
            Err(protocol::Error::from_errno(libc::EBADF))
        })
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    fn set_dead(&self) {
        self.alive.store(false, Ordering::Release);
    }
}

pub struct ServerClipboardChannel {
    ch: ServerGenericCommandChannel,
}

impl ServerClipboardChannel {
    pub fn new(
        logger: Arc<Logger>,
        id: ChannelID,
        cmd: Command,
        op: ClipboardChannelOperation,
    ) -> Result<ServerClipboardChannel, protocol::Error> {
        let mut cmd = cmd;
        match op {
            ClipboardChannelOperation::Copy => {
                cmd.stdin(Stdio::piped());
                cmd.stdout(Stdio::null());
            }
            ClipboardChannelOperation::Paste => {
                cmd.stdin(Stdio::null());
                cmd.stdout(Stdio::piped());
            }
        }
        cmd.stderr(Stdio::null());
        trace!(logger, "channel {}: spawn {:?}", id, cmd);
        let mut cmd = match cmd.spawn() {
            Ok(cmd) => cmd,
            Err(e) => return Err(e.into()),
        };
        trace!(logger, "channel {}: spawn ok: pid {}", id, cmd.id());
        let fds = (
            Self::file_from_command::<PipeWrite, _>(cmd.stdin.take()),
            Self::file_from_command::<PipeRead, _>(cmd.stdout.take()),
            None,
        );
        Ok(ServerClipboardChannel {
            ch: ServerGenericCommandChannel {
                cmd: Mutex::new(cmd),
                fds: Arc::new(sync::RwLock::new(fds)),
                exit_status: Mutex::new(None),
                id,
                logger,
                alive: AtomicBool::new(true),
            },
        })
    }

    fn file_from_command<F: FromRawFd, T: IntoRawFd>(io: Option<T>) -> Option<Arc<sync::Mutex<F>>> {
        let io = io?;
        Some(Arc::new(sync::Mutex::new(unsafe {
            F::from_raw_fd(io.into_raw_fd())
        })))
    }
}

impl Channel for ServerClipboardChannel {
    fn id(&self) -> ChannelID {
        self.ch.id()
    }

    fn read(&self, selector: u32) -> Result<Bytes, protocol::Error> {
        self.ch.read(selector)
    }

    fn write(&self, selector: u32, data: Bytes) -> Result<u64, protocol::Error> {
        self.ch.write(selector, data)
    }

    fn poll(
        &self,
        selectors: Vec<u32>,
        flags: Option<Vec<u64>>,
        duration: Duration,
        ch: oneshot::Sender<Result<Vec<protocol::PollChannelFlags>, protocol::Error>>,
    ) {
        self.ch.poll(selectors, flags, duration, ch)
    }

    fn ping(&self) -> Result<(), protocol::Error> {
        self.ch.ping()
    }

    fn detach_selector(&self, selector: u32) -> Result<(), protocol::Error> {
        self.ch.detach_selector(selector)
    }

    fn is_alive(&self) -> bool {
        self.ch.is_alive()
    }

    fn set_dead(&self) {
        self.ch.set_dead()
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Server9PSessionHandle {
    target: Bytes,
    location: Bytes,
    user: Bytes,
    nuname: Option<u32>,
    valid: bool,
}

impl ToIdentifier for Server9PSessionHandle {
    fn to_identifier(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(&(self.target.len() as u64).to_le_bytes());
        v.extend(&(self.location.len() as u64).to_le_bytes());
        v.extend(&(self.user.len() as u64).to_le_bytes());
        v.extend(&self.target);
        v.extend(&self.location);
        v.extend(&self.user);
        v
    }
}

pub struct Server9PAuthenticator {
    target: Bytes,
    location: Bytes,
    logger: Arc<Logger>,
}

impl Server9PAuthenticator {
    pub fn new(target: Bytes, location: Bytes, logger: Arc<Logger>) -> Self {
        Self {
            target,
            location,
            logger,
        }
    }
}

impl Authenticator for Server9PAuthenticator {
    type SessionHandle = Server9PSessionHandle;

    fn create(&self, uname: &[u8], aname: &[u8], nuname: Option<u32>) -> Self::SessionHandle {
        // TODO: implement logging trait
        trace!(
            self.logger,
            "9P authenticator: user {} location {} target {} nuname {:?} aname {} valid {}",
            hex::encode(uname),
            hex::encode(&self.location),
            hex::encode(&self.target),
            nuname,
            hex::encode(aname),
            aname == self.target
        );
        Server9PSessionHandle {
            user: uname.to_vec().into(),
            location: self.location.to_vec().into(),
            target: self.target.to_vec().into(),
            nuname,
            valid: aname == self.target || aname.is_empty(),
        }
    }

    fn read(&self, _handle: &mut Self::SessionHandle, _data: &mut [u8]) -> Result<u32, Errno> {
        Err(Errno::EOPNOTSUPP)
    }

    fn write(&self, _handle: &mut Self::SessionHandle, _data: &[u8]) -> Result<u32, Errno> {
        Err(Errno::EOPNOTSUPP)
    }

    fn info<'a>(&self, handle: &'a Self::SessionHandle) -> Option<AuthenticationInfo<'a>> {
        if !handle.valid {
            return None;
        }
        Some(AuthenticationInfo::new(
            handle.nuname,
            &handle.user,
            &handle.target,
            &handle.location,
        ))
    }
}

pub struct Server9PChannel {
    rd: Arc<sync::Mutex<Option<OwnedReadHalf>>>,
    wr: Arc<sync::Mutex<Option<OwnedWriteHalf>>>,
    rdwr: RawFd,
    alive: AtomicBool,
    exit_status: Arc<Mutex<Option<i32>>>,
    id: ChannelID,
    logger: Arc<Logger>,
}

impl Server9PChannel {
    pub fn new(
        logger: Arc<Logger>,
        id: ChannelID,
        target: Bytes,
        location: Bytes,
    ) -> Result<Server9PChannel, protocol::Error> {
        const BUFFER_SIZE: usize = 128 * 1024;
        let (str1, str2) = UnixStream::pair()?;
        let rdwr = str2.as_raw_fd();
        let (rd1, wr1) = str1.into_split();
        let (rd2, wr2) = str2.into_split();
        let exit_status = Arc::new(Mutex::new(None));
        let es = exit_status.clone();
        let serv = Server9P::new(
            logger.clone(),
            LibcBackend::new(
                logger.clone(),
                Server9PAuthenticator::new(target, location, logger.clone()),
                BUFFER_SIZE as u32,
            ),
            rd1,
            wr1,
        );
        let serv_logger = logger.clone();
        tokio::spawn(async move {
            let mut serv = serv;
            let r = serv.run().await;
            trace!(serv_logger, "channel {}: 9P server exiting: {:?}", id, &r);
            let mut g = es.lock().unwrap();
            *g = Some(if r.is_ok() { 0 } else { 3 });
        });
        Ok(Self {
            logger,
            id,
            rdwr,
            exit_status,
            alive: AtomicBool::new(true),
            rd: Arc::new(sync::Mutex::new(Some(rd2))),
            wr: Arc::new(sync::Mutex::new(Some(wr2))),
        })
    }
}

impl Channel for Server9PChannel {
    fn id(&self) -> ChannelID {
        self.id
    }

    fn read(&self, selector: u32) -> Result<Bytes, protocol::Error> {
        let fd = self.rd.clone();
        let logger = self.logger.clone();
        let id = self.id;
        block_on_async(async move {
            let mut g = fd.lock().await;
            match (selector, &mut *g) {
                (1, Some(reader)) => {
                    trace!(logger, "channel {}: reading {}", id, selector);
                    let mut buf = vec![0u8; 65536];
                    let n = match reader.try_read(&mut buf) {
                        Ok(n) => n,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            return Err(protocol::Error::from_errno(libc::EAGAIN));
                        }
                        Err(e) => {
                            trace!(
                                logger,
                                "channel {}: reading {} failed with {}",
                                id,
                                selector,
                                e
                            );
                            return Err(e.into());
                        }
                    };
                    trace!(logger, "channel {}: read {} bytes from {}", id, n, selector);
                    buf.truncate(n);
                    Ok(buf.into())
                }
                _ => {
                    trace!(
                        logger,
                        "channel {}: bad descriptor {} for reading",
                        id,
                        selector
                    );
                    Err(protocol::Error::from_errno(libc::EBADF))
                }
            }
        })
    }

    fn write(&self, selector: u32, data: Bytes) -> Result<u64, protocol::Error> {
        let fd = self.wr.clone();
        let logger = self.logger.clone();
        let id = self.id;
        block_on_async(async move {
            let mut g = fd.lock().await;
            match (selector, &mut *g) {
                (0, Some(writer)) => {
                    trace!(logger, "channel {}: writing {}", id, selector);
                    let n = match writer.try_write(&data) {
                        Ok(n) => n,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            return Err(protocol::Error::from_errno(libc::EAGAIN));
                        }
                        Err(e) => {
                            trace!(
                                logger,
                                "channel {}: writing {} failed with {}",
                                id,
                                selector,
                                e
                            );
                            return Err(e.into());
                        }
                    };
                    trace!(
                        logger,
                        "channel {}: wrote {} bytes from {}",
                        id,
                        data.len(),
                        selector
                    );
                    Ok(n as u64)
                }
                _ => {
                    trace!(
                        logger,
                        "channel {}: bad descriptor {} for writing",
                        id,
                        selector
                    );
                    Err(protocol::Error::from_errno(libc::EBADF))
                }
            }
        })
    }

    fn poll(
        &self,
        selectors: Vec<u32>,
        flags: Option<Vec<u64>>,
        duration: Duration,
        ch: oneshot::Sender<Result<Vec<protocol::PollChannelFlags>, protocol::Error>>,
    ) {
        let base_flags = {
            let g = self.exit_status.lock().unwrap();
            if g.is_some() {
                protocol::PollChannelFlags::Gone
            } else {
                protocol::PollChannelFlags::default()
            }
        };
        trace!(
            self.logger,
            "channel {}: poll: flags {:?}",
            self.id,
            base_flags
        );
        let id = self.id;
        let mut fds = Vec::new();
        for sel in &selectors {
            let f = match sel {
                0 => self.wr.blocking_lock().as_ref().map(|_| self.rdwr),
                1 => self.rd.blocking_lock().as_ref().map(|_| self.rdwr),
                _ => None,
            };
            let fd = match f {
                Some(f) => f,
                None => {
                    let _ = ch.send(Err(protocol::Error {
                        code: ResponseCode::InvalidParameters,
                        body: None,
                    }));
                    return;
                }
            };
            fds.push(fd);
        }
        poll(
            self.logger.clone(),
            selectors,
            flags,
            fds,
            id,
            duration,
            self.is_alive(),
            ch,
        );
    }

    fn ping(&self) -> Result<(), protocol::Error> {
        {
            let g = self.exit_status.lock().unwrap();
            if let Some(st) = *g {
                return Err(protocol::Error {
                    code: ResponseCode::Gone,
                    body: Some(ErrorBody::Exit(st)),
                });
            }
        }
        Ok(())
    }

    fn detach_selector(&self, selector: u32) -> Result<(), protocol::Error> {
        let rd = self.rd.clone();
        let wr = self.wr.clone();
        block_on_async(async move {
            match selector {
                0 => {
                    let mut g = wr.lock().await;
                    *g = None
                }
                1 => {
                    let mut g = rd.lock().await;
                    *g = None
                }
                _ => return Err(protocol::Error::from_errno(libc::EBADF)),
            }
            Ok(())
        })
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    fn set_dead(&self) {
        self.alive.store(false, Ordering::Release);
    }
}
