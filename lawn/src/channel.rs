#![allow(dead_code)]

use crate::config::Logger;
use crate::task::block_on_async;
use crate::unix;
use bytes::{Bytes, BytesMut};
use lawn_9p::backend::libc::LibcBackend;
use lawn_9p::server::Server as Server9P;
use lawn_constants::error::Error as Errno;
use lawn_fs::auth::{AuthenticationInfo, Authenticator, AuthenticatorHandle};
use lawn_fs::backend::Metadata;
use lawn_protocol::protocol;
use lawn_protocol::protocol::{ChannelID, ClipboardChannelOperation, ErrorBody, ResponseCode};
use lawn_sftp::backend::Backend as SFTPBackend;
use lawn_sftp::server::Server as ServerSFTP;
use std::cmp::{self, Eq, Ord, PartialEq, PartialOrd};
use std::collections::HashMap;
use std::convert::TryInto;
use std::future::Future;
use std::io;
use std::os::raw::c_int;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
        g.get(&id).cloned()
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

#[allow(clippy::arc_with_non_send_sync)]
fn readable_file_from_command<F: FromRawFd + Readable + 'static, T: IntoRawFd>(
    io: Option<T>,
) -> Option<Arc<sync::Mutex<dyn Readable>>> {
    let io = io?;
    Some(Arc::new(sync::Mutex::new(unsafe {
        F::from_raw_fd(io.into_raw_fd())
    })))
}

#[allow(clippy::arc_with_non_send_sync)]
fn writable_file_from_command<F: FromRawFd + Writable + 'static, T: IntoRawFd>(
    io: Option<T>,
) -> Option<Arc<sync::Mutex<dyn Writable>>> {
    let io = io?;
    Some(Arc::new(sync::Mutex::new(unsafe {
        F::from_raw_fd(io.into_raw_fd())
    })))
}

pub struct ChannelCommandQueue {
    logger: Arc<Logger>,
    waiter: sync::Notify,
    offset: Locked<u64>,
    abort: AtomicBool,
}

impl ChannelCommandQueue {
    fn new(logger: Arc<Logger>, offset: Locked<u64>) -> Self {
        let waiter = sync::Notify::new();
        waiter.notify_one();
        Self {
            logger,
            waiter,
            offset,
            abort: AtomicBool::new(false),
        }
    }

    async fn process_request<
        'a,
        T,
        U,
        Fut: Future<Output = Result<T, protocol::Error>> + Send,
        F: FnOnce(sync::MutexGuard<'a, u64>, U) -> Fut,
    >(
        &'a self,
        id: ChannelID,
        offset: u64,
        data: U,
        task: F,
    ) -> Result<T, protocol::Error> {
        loop {
            trace!(
                self.logger,
                "channel {}: waiting on lock for offset {}",
                id,
                offset
            );
            self.waiter.notified().await;
            trace!(
                self.logger,
                "channel {}: trying op for offset {}",
                id,
                offset
            );
            let soff = self.offset.lock().await;
            match offset.cmp(&*soff) {
                cmp::Ordering::Less => {
                    trace!(
                        self.logger,
                        "channel {}: stale request at offset {} (current {})",
                        id,
                        offset,
                        *soff
                    );
                    self.waiter.notify_one();
                    return Err(ResponseCode::Conflict.into());
                }
                cmp::Ordering::Equal => {
                    trace!(
                        self.logger,
                        "channel {}: running op at offset {}",
                        id,
                        offset
                    );
                    let res = task(soff, data).await;
                    self.waiter.notify_one();
                    return res;
                }
                cmp::Ordering::Greater => {
                    trace!(
                        self.logger,
                        "channel {}: not yet ready at offset {} (current {})",
                        id,
                        offset,
                        *soff
                    );
                }
            }
            self.waiter.notify_one();
        }
    }
}

pub trait Channel {
    fn id(&self) -> ChannelID;
    fn read(
        &self,
        selector: u32,
        count: u64,
        sync: Option<u64>,
        blocking: Option<bool>,
        complete: bool,
    ) -> Result<Bytes, protocol::Error>;
    fn write(
        &self,
        selector: u32,
        data: Bytes,
        sync: Option<u64>,
        blocking: Option<bool>,
    ) -> Result<u64, protocol::Error>;
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

trait Readable: AsyncRead + AsRawFd + Unpin + Send + Sync {}
trait Writable: AsyncWrite + AsRawFd + Unpin + Send + Sync {}

impl<T: AsyncRead + AsRawFd + Unpin + Send + Sync> Readable for T {}
impl<T: AsyncWrite + AsRawFd + Unpin + Send + Sync> Writable for T {}

type Locked<T> = Arc<sync::Mutex<T>>;
type OptionLocked<T> = Option<Arc<sync::Mutex<T>>>;
type OptionLockedWrite = OptionLocked<dyn Writable>;
type OptionLockedRead = OptionLocked<dyn Readable>;
type FDSet = Arc<sync::RwLock<(OptionLockedWrite, OptionLockedRead, OptionLockedRead)>>;
type LockedU64 = Locked<u64>;

pub struct ServerGenericCommandChannel {
    // TODO: take the FDs out of the child and handle them individually
    cmd: Mutex<Child>,
    fds: Arc<sync::RwLock<(OptionLockedWrite, OptionLockedRead, OptionLockedRead)>>,
    exit_status: Mutex<Option<ExitStatus>>,
    id: ChannelID,
    logger: Arc<Logger>,
    alive: AtomicBool,
    bytes: Arc<sync::RwLock<(LockedU64, LockedU64, LockedU64)>>,
    queue: Arc<(
        ChannelCommandQueue,
        ChannelCommandQueue,
        ChannelCommandQueue,
    )>,
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

    async fn do_write(
        logger: Arc<Logger>,
        id: ChannelID,
        io: Locked<dyn Writable>,
        data: Bytes,
        blocking: bool,
        guard: sync::MutexGuard<'_, u64>,
    ) -> Result<u64, protocol::Error> {
        let mut guard = guard;
        let mut g = io.lock().await;
        let mut off = 0;
        while !blocking || off < data.len() {
            trace!(logger, "channel {}: write", id);
            let res = g.write(&data[off..]).await;
            trace!(logger, "channel {}: write: {:?}", id, res);
            match res {
                Ok(n) => {
                    *guard += n as u64;
                    off += n;
                }
                Err(e) => {
                    if off == 0 {
                        return Err(e.into());
                    } else {
                        return Ok(off as u64);
                    }
                }
            }
            if !blocking {
                break;
            }
        }
        Ok(off as u64)
    }

    async fn do_read(
        logger: Arc<Logger>,
        id: ChannelID,
        io: Locked<dyn Readable>,
        count: u64,
        blocking: bool,
        complete: bool,
        guard: sync::MutexGuard<'_, u64>,
    ) -> Result<Bytes, protocol::Error> {
        let mut guard = guard;
        let mut g = io.lock().await;
        let mut off = 0;
        let count: usize = match count.try_into() {
            Ok(c) => c,
            Err(_) => return Err(protocol::ResponseCode::InvalidParameters.into()),
        };
        // It doesn't make sense to try to read a complete buffer if we're not blocking.
        let complete = complete && blocking;
        let mut buf = BytesMut::zeroed(count);
        while !complete || off < buf.len() {
            trace!(logger, "channel {}: read", id);
            let res = g.read(&mut buf[off..]).await;
            trace!(logger, "channel {}: read: {:?}", id, res);
            match res {
                Ok(n) => {
                    *guard += n as u64;
                    off += n;
                    if n == 0 {
                        break;
                    }
                }
                Err(e) => {
                    if off == 0 {
                        return Err(e.into());
                    } else {
                        buf.truncate(off);
                        return Ok(buf.into());
                    }
                }
            }
            if !complete {
                break;
            }
        }
        buf.truncate(off);
        Ok(buf.into())
    }

    async fn do_write_blocking(
        logger: Arc<Logger>,
        id: ChannelID,
        queue: &ChannelCommandQueue,
        io: Locked<dyn Writable>,
        data: Bytes,
        sync: Option<u64>,
    ) -> Result<u64, protocol::Error> {
        match sync {
            Some(syncoff) => {
                trace!(
                    logger,
                    "channel {}: write: entering queue at offset {}",
                    id,
                    syncoff
                );
                queue
                    .process_request(id, syncoff, data, move |guard, data| {
                        Self::do_write(logger, id, io, data, true, guard)
                    })
                    .await
            }
            None => {
                let guard = queue.offset.lock().await;
                Self::do_write(logger, id, io, data, true, guard).await
            }
        }
    }

    async fn do_read_blocking(
        logger: Arc<Logger>,
        id: ChannelID,
        queue: &ChannelCommandQueue,
        io: Locked<dyn Readable>,
        count: u64,
        sync: Option<u64>,
        complete: bool,
    ) -> Result<Bytes, protocol::Error> {
        match sync {
            Some(syncoff) => {
                trace!(
                    logger,
                    "channel {}: read: entering queue at offset {}",
                    id,
                    syncoff
                );
                queue
                    .process_request(id, syncoff, count, move |guard, count| {
                        Self::do_read(logger, id, io, count, true, complete, guard)
                    })
                    .await
            }
            None => {
                let guard = queue.offset.lock().await;
                Self::do_read(logger, id, io, count, true, complete, guard).await
            }
        }
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
        let mut cmd = cmd.spawn()?;
        trace!(logger, "channel {}: spawn ok: pid {}", id, cmd.id());
        let fds = (
            writable_file_from_command::<PipeWrite, _>(cmd.stdin.take()),
            readable_file_from_command::<PipeRead, _>(cmd.stdout.take()),
            readable_file_from_command::<PipeRead, _>(cmd.stderr.take()),
        );
        let bytes = (
            Arc::new(sync::Mutex::new(0)),
            Arc::new(sync::Mutex::new(0)),
            Arc::new(sync::Mutex::new(0)),
        );
        Ok(ServerCommandChannel {
            ch: ServerGenericCommandChannel {
                cmd: Mutex::new(cmd),
                fds: Arc::new(sync::RwLock::new(fds)),
                exit_status: Mutex::new(None),
                id,
                queue: Arc::new((
                    ChannelCommandQueue::new(logger.clone(), bytes.0.clone()),
                    ChannelCommandQueue::new(logger.clone(), bytes.1.clone()),
                    ChannelCommandQueue::new(logger.clone(), bytes.2.clone()),
                )),
                bytes: Arc::new(sync::RwLock::new(bytes)),
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

    fn read(
        &self,
        selector: u32,
        count: u64,
        sync: Option<u64>,
        blocking: Option<bool>,
        complete: bool,
    ) -> Result<Bytes, protocol::Error> {
        self.ch.read(selector, count, sync, blocking, complete)
    }

    fn write(
        &self,
        selector: u32,
        data: Bytes,
        sync: Option<u64>,
        blocking: Option<bool>,
    ) -> Result<u64, protocol::Error> {
        self.ch.write(selector, data, sync, blocking)
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

    fn read(
        &self,
        selector: u32,
        count: u64,
        sync: Option<u64>,
        blocking: Option<bool>,
        complete: bool,
    ) -> Result<Bytes, protocol::Error> {
        let fds = self.fds.clone();
        let bytes = self.bytes.clone();
        let id = self.id;
        let queue = self.queue.clone();
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
            if blocking == Some(true) {
                let queue = match selector {
                    1 => &queue.1,
                    2 => &queue.2,
                    _ => return Err(protocol::Error::from_errno(libc::EBADF)),
                };
                Self::do_read_blocking(logger, id, queue, io, count, sync, complete).await
            } else {
                let gbytes = bytes.read().await;
                let bytes_written = {
                    match selector {
                        1 => &gbytes.1,
                        2 => &gbytes.2,
                        _ => return Err(protocol::Error::from_errno(libc::EBADF)),
                    }
                    .clone()
                };
                let guard = bytes_written.lock().await;
                Self::do_read(logger, id, io, count, false, false, guard).await
            }
        })
    }

    fn write(
        &self,
        selector: u32,
        data: Bytes,
        sync: Option<u64>,
        blocking: Option<bool>,
    ) -> Result<u64, protocol::Error> {
        let fds = self.fds.clone();
        let bytes = self.bytes.clone();
        let queue = self.queue.clone();
        let id = self.id;
        let logger = self.logger.clone();
        let blocking = blocking == Some(true);
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
            if blocking {
                let queue = match selector {
                    0 => &queue.0,
                    _ => return Err(protocol::Error::from_errno(libc::EBADF)),
                };
                Self::do_write_blocking(logger, id, queue, io, data, sync).await
            } else {
                let gbytes = bytes.read().await;
                let bytes_written = {
                    match selector {
                        0 => &gbytes.0,
                        _ => return Err(protocol::Error::from_errno(libc::EBADF)),
                    }
                    .clone()
                };
                let guard = bytes_written.lock().await;
                Self::do_write(logger, id, io, data, false, guard).await
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
        let fds: Vec<_> = selectors
            .iter()
            .map(|s| self.fd_from_selector(*s).unwrap_or(-1))
            .collect();
        poll(
            logger,
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
        let mut cmd = cmd.spawn()?;
        trace!(logger, "channel {}: spawn ok: pid {}", id, cmd.id());
        let fds = (
            writable_file_from_command::<PipeWrite, _>(cmd.stdin.take()),
            readable_file_from_command::<PipeRead, _>(cmd.stdout.take()),
            None,
        );
        let bytes = (
            Arc::new(sync::Mutex::new(0)),
            Arc::new(sync::Mutex::new(0)),
            Arc::new(sync::Mutex::new(0)),
        );
        Ok(ServerClipboardChannel {
            ch: ServerGenericCommandChannel {
                cmd: Mutex::new(cmd),
                fds: Arc::new(sync::RwLock::new(fds)),
                exit_status: Mutex::new(None),
                id,
                queue: Arc::new((
                    ChannelCommandQueue::new(logger.clone(), bytes.0.clone()),
                    ChannelCommandQueue::new(logger.clone(), bytes.1.clone()),
                    ChannelCommandQueue::new(logger.clone(), bytes.2.clone()),
                )),
                bytes: Arc::new(sync::RwLock::new(bytes)),
                logger,
                alive: AtomicBool::new(true),
            },
        })
    }
}

impl Channel for ServerClipboardChannel {
    fn id(&self) -> ChannelID {
        self.ch.id()
    }

    fn read(
        &self,
        selector: u32,
        count: u64,
        sync: Option<u64>,
        blocking: Option<bool>,
        complete: bool,
    ) -> Result<Bytes, protocol::Error> {
        self.ch.read(selector, count, sync, blocking, complete)
    }

    fn write(
        &self,
        selector: u32,
        data: Bytes,
        sync: Option<u64>,
        blocking: Option<bool>,
    ) -> Result<u64, protocol::Error> {
        self.ch.write(selector, data, sync, blocking)
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
pub struct ServerFSSessionHandle {
    target: Bytes,
    location: Bytes,
    user: Bytes,
    nuname: Option<u32>,
    valid: bool,
}

impl AuthenticatorHandle for ServerFSSessionHandle {
    fn read(&self, _data: &mut [u8]) -> Result<u32, Errno> {
        Err(Errno::EOPNOTSUPP)
    }

    fn write(&self, _data: &[u8]) -> Result<u32, Errno> {
        Err(Errno::EOPNOTSUPP)
    }

    fn info(&self) -> Option<AuthenticationInfo<'_>> {
        if !self.valid {
            return None;
        }
        Some(AuthenticationInfo::new(
            self.nuname,
            &self.user,
            &self.target,
            &self.location,
        ))
    }
}

pub struct ServerFSAuthenticator {
    target: Bytes,
    location: Bytes,
    logger: Arc<Logger>,
}

impl ServerFSAuthenticator {
    pub fn new(target: Bytes, location: Bytes, logger: Arc<Logger>) -> Self {
        Self {
            target,
            location,
            logger,
        }
    }
}

impl Authenticator for ServerFSAuthenticator {
    fn create(
        &self,
        _meta: &Metadata,
        uname: &[u8],
        aname: &[u8],
        nuname: Option<u32>,
    ) -> Box<dyn AuthenticatorHandle + Send + Sync> {
        // TODO: implement logging trait
        trace!(
            self.logger,
            "FS authenticator: user {} location {} target {} nuname {:?} aname {} valid {}",
            hex::encode(uname),
            hex::encode(&self.location),
            hex::encode(&self.target),
            nuname,
            hex::encode(aname),
            aname == self.target
        );
        Box::new(ServerFSSessionHandle {
            user: uname.to_vec().into(),
            location: self.location.to_vec().into(),
            target: self.target.to_vec().into(),
            nuname,
            valid: aname == self.target || aname.is_empty(),
        })
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
    bytes: Arc<sync::RwLock<(Locked<u64>, Locked<u64>)>>,
    queue: Arc<(ChannelCommandQueue, ChannelCommandQueue)>,
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
                Arc::new(lawn_fs::backend::libc::LibcBackend::new(
                    logger.clone(),
                    Arc::new(ServerFSAuthenticator::new(target, location, logger.clone())),
                    BUFFER_SIZE as u32,
                )),
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
        let rd = Arc::new(sync::Mutex::new(Some(rd2)));
        let wr = Arc::new(sync::Mutex::new(Some(wr2)));
        let bytes = (Arc::new(sync::Mutex::new(0)), Arc::new(sync::Mutex::new(0)));
        Ok(Self {
            logger: logger.clone(),
            id,
            rdwr,
            exit_status,
            alive: AtomicBool::new(true),
            rd,
            wr,
            queue: Arc::new((
                ChannelCommandQueue::new(logger.clone(), bytes.0.clone()),
                ChannelCommandQueue::new(logger.clone(), bytes.1.clone()),
            )),
            bytes: Arc::new(sync::RwLock::new(bytes)),
        })
    }
}

impl FSChannel for Server9PChannel {
    fn rd(&self) -> Arc<sync::Mutex<Option<OwnedReadHalf>>> {
        self.rd.clone()
    }

    fn wr(&self) -> Arc<sync::Mutex<Option<OwnedWriteHalf>>> {
        self.wr.clone()
    }

    fn rd_bytes(&self) -> Locked<u64> {
        self.bytes.blocking_read().1.clone()
    }

    fn wr_bytes(&self) -> Locked<u64> {
        self.bytes.blocking_read().0.clone()
    }

    fn queue(&self) -> Arc<(ChannelCommandQueue, ChannelCommandQueue)> {
        self.queue.clone()
    }

    fn fd(&self) -> RawFd {
        self.rdwr
    }

    fn alive(&self) -> &AtomicBool {
        &self.alive
    }

    fn exit_status(&self) -> Arc<Mutex<Option<i32>>> {
        self.exit_status.clone()
    }

    fn channel_id(&self) -> ChannelID {
        self.id
    }

    fn logger(&self) -> Arc<Logger> {
        self.logger.clone()
    }
}

pub struct ServerSFTPChannel {
    rd: Arc<sync::Mutex<Option<OwnedReadHalf>>>,
    wr: Arc<sync::Mutex<Option<OwnedWriteHalf>>>,
    rdwr: RawFd,
    alive: AtomicBool,
    exit_status: Arc<Mutex<Option<i32>>>,
    id: ChannelID,
    logger: Arc<Logger>,
    bytes: Arc<sync::RwLock<(Locked<u64>, Locked<u64>)>>,
    queue: Arc<(ChannelCommandQueue, ChannelCommandQueue)>,
}

impl ServerSFTPChannel {
    pub fn new(
        logger: Arc<Logger>,
        id: ChannelID,
        target: Bytes,
        location: Bytes,
    ) -> Result<ServerSFTPChannel, protocol::Error> {
        const BUFFER_SIZE: usize = 128 * 1024;
        let (str1, str2) = UnixStream::pair()?;
        let rdwr = str2.as_raw_fd();
        let (rd1, wr1) = str1.into_split();
        let (rd2, wr2) = str2.into_split();
        let exit_status = Arc::new(Mutex::new(None));
        let es = exit_status.clone();
        let serv_logger = logger.clone();
        let backend = SFTPBackend::new(
            logger.clone(),
            Arc::new(lawn_fs::backend::libc::LibcBackend::new(
                logger.clone(),
                Arc::new(ServerFSAuthenticator::new(
                    target.clone(),
                    location,
                    logger.clone(),
                )),
                BUFFER_SIZE as u32,
            )),
            None,
            &target,
        );
        let backend = backend.map_err(io::Error::from)?;
        let serv = ServerSFTP::new(logger.clone(), backend, rd1, wr1);
        tokio::spawn(async move {
            let mut serv = serv;
            let r = serv.run().await;
            trace!(serv_logger, "channel {}: SFTP server exiting: {:?}", id, &r);
            let mut g = es.lock().unwrap();
            *g = Some(if r.is_ok() { 0 } else { 3 });
        });
        let rd = Arc::new(sync::Mutex::new(Some(rd2)));
        let wr = Arc::new(sync::Mutex::new(Some(wr2)));
        let bytes = (Arc::new(sync::Mutex::new(0)), Arc::new(sync::Mutex::new(0)));
        Ok(Self {
            logger: logger.clone(),
            id,
            rdwr,
            exit_status,
            alive: AtomicBool::new(true),
            rd,
            wr,
            queue: Arc::new((
                ChannelCommandQueue::new(logger.clone(), bytes.0.clone()),
                ChannelCommandQueue::new(logger.clone(), bytes.1.clone()),
            )),
            bytes: Arc::new(sync::RwLock::new(bytes)),
        })
    }
}

impl FSChannel for ServerSFTPChannel {
    fn rd(&self) -> Arc<sync::Mutex<Option<OwnedReadHalf>>> {
        self.rd.clone()
    }

    fn wr(&self) -> Arc<sync::Mutex<Option<OwnedWriteHalf>>> {
        self.wr.clone()
    }

    fn rd_bytes(&self) -> Locked<u64> {
        self.bytes.blocking_read().1.clone()
    }

    fn wr_bytes(&self) -> Locked<u64> {
        self.bytes.blocking_read().0.clone()
    }

    fn queue(&self) -> Arc<(ChannelCommandQueue, ChannelCommandQueue)> {
        self.queue.clone()
    }

    fn fd(&self) -> RawFd {
        self.rdwr
    }

    fn alive(&self) -> &AtomicBool {
        &self.alive
    }

    fn exit_status(&self) -> Arc<Mutex<Option<i32>>> {
        self.exit_status.clone()
    }

    fn channel_id(&self) -> ChannelID {
        self.id
    }

    fn logger(&self) -> Arc<Logger> {
        self.logger.clone()
    }
}

pub trait FSChannel {
    fn rd(&self) -> Arc<sync::Mutex<Option<OwnedReadHalf>>>;
    fn wr(&self) -> Arc<sync::Mutex<Option<OwnedWriteHalf>>>;
    fn fd(&self) -> RawFd;
    fn alive(&self) -> &AtomicBool;
    fn exit_status(&self) -> Arc<Mutex<Option<i32>>>;
    fn channel_id(&self) -> ChannelID;
    fn logger(&self) -> Arc<Logger>;
    fn rd_bytes(&self) -> Locked<u64>;
    fn wr_bytes(&self) -> Locked<u64>;
    fn queue(&self) -> Arc<(ChannelCommandQueue, ChannelCommandQueue)>;
}

async fn fs_channel_do_read(
    logger: Arc<Logger>,
    id: ChannelID,
    selector: u32,
    reader: Arc<sync::Mutex<Option<OwnedReadHalf>>>,
    count: u64,
    complete: bool,
    guard: sync::MutexGuard<'_, u64>,
) -> Result<Bytes, protocol::Error> {
    let mut guard = guard;
    trace!(
        logger,
        "channel {}: reading {} (blocking) (complete {})",
        id,
        selector,
        complete
    );
    if count > 64 * 1024 {
        return Err(protocol::ResponseCode::InvalidParameters.into());
    }
    let mut buf = BytesMut::with_capacity(count as usize);
    let mut off = 0;
    let mut lock = reader.lock().await;
    let reader = match &mut *lock {
        Some(reader) => reader,
        None => return Err(protocol::Error::from_errno(libc::EBADF)),
    };
    while off < buf.capacity() {
        trace!(
            logger,
            "channel {}: reading {}: waiting for server to be readable",
            id,
            selector,
        );
        let n = match reader.read_buf(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                trace!(
                    logger,
                    "channel {}: reading {} failed with {}",
                    id,
                    selector,
                    e
                );
                if off == 0 {
                    return Err(e.into());
                } else {
                    *guard += off as u64;
                    return Ok(buf.into());
                }
            }
        };
        off += n;
        if !complete || n == 0 {
            break;
        }
    }
    trace!(
        logger,
        "channel {}: read {} bytes from {}",
        id,
        off,
        selector
    );
    *guard += off as u64;
    Ok(buf.into())
}

async fn fs_channel_do_write(
    logger: Arc<Logger>,
    id: ChannelID,
    selector: u32,
    writer: Arc<sync::Mutex<Option<OwnedWriteHalf>>>,
    data: Bytes,
    guard: sync::MutexGuard<'_, u64>,
) -> Result<u64, protocol::Error> {
    let mut guard = guard;
    trace!(logger, "channel {}: writing {} (blocking)", id, selector);
    let mut off = 0;
    let mut lock = writer.lock().await;
    let writer = match &mut *lock {
        Some(writer) => writer,
        None => return Err(protocol::Error::from_errno(libc::EBADF)),
    };
    while off < data.len() {
        let n = match writer.write(&data[off..]).await {
            Ok(n) => n,
            Err(e) => {
                trace!(
                    logger,
                    "channel {}: writing {} failed with {}",
                    id,
                    selector,
                    e
                );
                if off == 0 {
                    return Err(e.into());
                } else {
                    *guard += off as u64;
                    return Ok(off as u64);
                }
            }
        };
        off += n;
        if n == 0 {
            break;
        }
    }
    trace!(
        logger,
        "channel {}: wrote {} bytes to {}",
        id,
        off,
        selector
    );
    *guard += off as u64;
    Ok(off as u64)
}

impl<T: FSChannel> Channel for T {
    fn id(&self) -> ChannelID {
        self.channel_id()
    }

    fn read(
        &self,
        selector: u32,
        count: u64,
        sync: Option<u64>,
        blocking: Option<bool>,
        complete: bool,
    ) -> Result<Bytes, protocol::Error> {
        let reader = self.rd();
        let logger = self.logger();
        let id = self.channel_id();
        let rd_bytes = self.rd_bytes();
        let queue = self.queue();
        block_on_async(async move {
            match (selector, blocking) {
                (1, Some(false)) | (1, None) => {
                    trace!(
                        logger,
                        "channel {}: reading {} (non-blocking)",
                        id,
                        selector
                    );
                    let mut buf = vec![0u8; std::cmp::min(count, 65536) as usize];
                    let mut lock = reader.lock().await;
                    let reader = match &mut *lock {
                        Some(reader) => reader,
                        None => return Err(protocol::Error::from_errno(libc::EBADF)),
                    };
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
                    let mut gbytes = rd_bytes.lock().await;
                    *gbytes += n as u64;
                    Ok(buf.into())
                }
                (1, Some(true)) => {
                    trace!(
                        logger,
                        "channel {}: reading {} (blocking) at offset {:?}",
                        id,
                        selector,
                        sync,
                    );
                    let guard = rd_bytes.lock().await;
                    match sync {
                        Some(syncoff) => {
                            trace!(
                                logger,
                                "channel {}: read: entering queue at offset {}",
                                id,
                                syncoff
                            );
                            let queue = &queue.1;
                            queue
                                .process_request(id, syncoff, count, move |guard, count| {
                                    fs_channel_do_read(
                                        logger.clone(),
                                        id,
                                        selector,
                                        reader,
                                        count,
                                        complete,
                                        guard,
                                    )
                                })
                                .await
                        }
                        None => {
                            fs_channel_do_read(
                                logger.clone(),
                                id,
                                selector,
                                reader,
                                count,
                                complete,
                                guard,
                            )
                            .await
                        }
                    }
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

    fn write(
        &self,
        selector: u32,
        data: Bytes,
        sync: Option<u64>,
        blocking: Option<bool>,
    ) -> Result<u64, protocol::Error> {
        let writer = self.wr();
        let logger = self.logger();
        let id = self.channel_id();
        let wr_bytes = self.wr_bytes();
        let queue = self.queue();
        block_on_async(async move {
            match (selector, blocking) {
                (0, Some(false)) | (0, None) => {
                    let mut lock = writer.lock().await;
                    let writer = match &mut *lock {
                        Some(writer) => writer,
                        None => return Err(protocol::Error::from_errno(libc::EBADF)),
                    };
                    trace!(
                        logger,
                        "channel {}: writing {} (non-blocking)",
                        id,
                        selector
                    );
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
                (0, Some(true)) => match sync {
                    Some(syncoff) => {
                        trace!(
                            logger,
                            "channel {}: write: entering queue at offset {}",
                            id,
                            syncoff
                        );
                        let queue = &queue.0;
                        queue
                            .process_request(id, syncoff, data, move |guard, data| {
                                fs_channel_do_write(
                                    logger.clone(),
                                    id,
                                    selector,
                                    writer,
                                    data,
                                    guard,
                                )
                            })
                            .await
                    }
                    None => {
                        let guard = wr_bytes.lock().await;
                        fs_channel_do_write(logger.clone(), id, selector, writer, data, guard).await
                    }
                },
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
            let exit_status = self.exit_status();
            let g = exit_status.lock().unwrap();
            if g.is_some() {
                protocol::PollChannelFlags::Gone
            } else {
                protocol::PollChannelFlags::default()
            }
        };
        trace!(
            self.logger(),
            "channel {}: poll: flags {:?}",
            self.channel_id(),
            base_flags
        );
        let id = self.channel_id();
        let mut fds = Vec::new();
        for sel in &selectors {
            let f = match sel {
                0 => self.wr().blocking_lock().as_ref().map(|_| self.fd()),
                1 => self.rd().blocking_lock().as_ref().map(|_| self.fd()),
                _ => None,
            };
            fds.push(f.unwrap_or(-1));
        }
        poll(
            self.logger(),
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
            let exit_status = self.exit_status();
            let g = exit_status.lock().unwrap();
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
        let rd = self.rd();
        let wr = self.wr();
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
        self.alive().load(Ordering::Acquire)
    }

    fn set_dead(&self) {
        self.alive().store(false, Ordering::Release);
    }
}
