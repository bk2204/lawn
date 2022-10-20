#![allow(dead_code)]

use crate::config::Logger;
use crate::task::block_on_async;
use crate::unix;
use bytes::Bytes;
use lawn_protocol::protocol;
use lawn_protocol::protocol::{ChannelID, ClipboardChannelOperation, ErrorBody, ResponseCode};
use std::collections::HashMap;
use std::os::raw::c_int;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::select;
use tokio::sync;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;

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

fn poll(
    logger: Arc<Logger>,
    selectors: Vec<u32>,
    fds: Vec<RawFd>,
    id: ChannelID,
    duration: Duration,
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
        for fd in fds {
            pfd.push(libc::pollfd {
                fd,
                events: libc::POLLIN | libc::POLLOUT | libc::POLLHUP,
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
        delay: Duration,
        ch: oneshot::Sender<Result<Vec<protocol::PollChannelFlags>, protocol::Error>>,
    );
    fn ping(&self) -> Result<(), protocol::Error>;
    fn detach_selector(&self, selector: u32) -> Result<(), protocol::Error>;
    fn is_alive(&self) -> bool;
    fn set_dead(&self);
}

type OptionLockedFile = Option<Arc<sync::Mutex<File>>>;

pub struct ServerGenericCommandChannel {
    // TODO: take the FDs out of the child and handle them individually
    cmd: Mutex<Child>,
    fds: RwLock<(OptionLockedFile, OptionLockedFile, OptionLockedFile)>,
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
        let g = self.fds.read().unwrap();
        let io = match selector {
            0 => g.0.clone(),
            1 => g.1.clone(),
            2 => g.2.clone(),
            _ => return None,
        };
        block_on_async(async {
            match io {
                Some(file) => Some(file.lock().await.as_raw_fd()),
                None => None,
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
        trace!(
            logger,
            "channel {}: spawn ok: pid {}",
            id,
            cmd.id().unwrap()
        );
        let fds = (
            Some(Arc::new(sync::Mutex::new(unsafe {
                File::from_raw_fd(cmd.stdin.as_ref().unwrap().as_raw_fd())
            }))),
            Some(Arc::new(sync::Mutex::new(unsafe {
                File::from_raw_fd(cmd.stdout.as_ref().unwrap().as_raw_fd())
            }))),
            Some(Arc::new(sync::Mutex::new(unsafe {
                File::from_raw_fd(cmd.stderr.as_ref().unwrap().as_raw_fd())
            }))),
        );
        Ok(ServerCommandChannel {
            ch: ServerGenericCommandChannel {
                cmd: Mutex::new(cmd),
                fds: RwLock::new(fds),
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
        duration: Duration,
        ch: oneshot::Sender<Result<Vec<protocol::PollChannelFlags>, protocol::Error>>,
    ) {
        self.ch.poll(selectors, duration, ch)
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
        let io = {
            let g = self.fds.read().unwrap();
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
        let id = self.id;
        let logger = self.logger.clone();
        block_on_async(async move {
            let mut v = vec![0u8; 4096];
            let mut g = io.lock().await;
            let mut interval = tokio::time::interval(Duration::from_millis(10));
            trace!(logger, "channel {}: read", id);
            select! {
                res = g.read(&mut v) => {
                    trace!(logger, "channel {}: read: {:?}", id, res);
                    match res {
                        Ok(n) => Ok(v[..n].to_vec().into()),
                        Err(e) => Err(e.into()),
                    }
                },
                _ = interval.tick() => {
                    trace!(logger, "channel {}: read: EAGAIN", id);
                    Err(protocol::Error::from_errno(libc::EAGAIN))
                }
            }
        })
    }

    fn write(&self, selector: u32, data: Bytes) -> Result<u64, protocol::Error> {
        let io = {
            let g = self.fds.read().unwrap();
            let io = match selector {
                0 => &g.0,
                _ => return Err(protocol::Error::from_errno(libc::EBADF)),
            };
            match io {
                Some(io) => io.clone(),
                None => return Err(protocol::Error::from_errno(libc::EBADF)),
            }
        };
        let id = self.id;
        let logger = self.logger.clone();
        block_on_async(async move {
            let mut g = io.lock().await;
            let mut interval = tokio::time::interval(Duration::from_millis(10));
            trace!(logger, "channel {}: write", id);
            select! {
                res = g.write(&data) => {
                    trace!(logger, "channel {}: write: {:?}", id, res);
                    match res {
                        Ok(n) => Ok(n as u64),
                        Err(e) => Err(e.into())
                    }
                },
                _ = interval.tick() => {
                    trace!(logger, "channel {}: read: EAGAIN", id);
                    Err(protocol::Error::from_errno(libc::EAGAIN))
                }
            }
        })
    }

    fn poll(
        &self,
        selectors: Vec<u32>,
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
            Ok(fds) => poll(logger, selectors, fds, id, duration, ch),
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
        let mut g = self.fds.write().unwrap();
        match selector {
            0 => {
                if g.0.is_some() {
                    g.0 = None;
                    return Ok(());
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
        let cmd = match cmd.spawn() {
            Ok(cmd) => cmd,
            Err(e) => return Err(e.into()),
        };
        trace!(
            logger,
            "channel {}: spawn ok: pid {}",
            id,
            cmd.id().unwrap()
        );
        let fds = (
            Self::file_from_command(cmd.stdin.as_ref()),
            Self::file_from_command(cmd.stdout.as_ref()),
            None,
        );
        Ok(ServerClipboardChannel {
            ch: ServerGenericCommandChannel {
                cmd: Mutex::new(cmd),
                fds: RwLock::new(fds),
                exit_status: Mutex::new(None),
                id,
                logger,
                alive: AtomicBool::new(true),
            },
        })
    }

    fn file_from_command<T: AsRawFd>(io: Option<&T>) -> Option<Arc<sync::Mutex<File>>> {
        let io = io?;
        Some(Arc::new(sync::Mutex::new(unsafe {
            File::from_raw_fd(io.as_raw_fd())
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
        duration: Duration,
        ch: oneshot::Sender<Result<Vec<protocol::PollChannelFlags>, protocol::Error>>,
    ) {
        self.ch.poll(selectors, duration, ch)
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
