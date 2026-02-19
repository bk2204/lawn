#![allow(dead_code)]

use crate::config::Config;
use crate::config::Logger as LoggerImpl;
use crate::encoding::{escape, path};
use crate::error::{Error, ErrorKind};
use crate::tty::TTYSettings;
use bytes::{Bytes, BytesMut};
use lawn_protocol::config::Logger;
use lawn_protocol::handler;
use lawn_protocol::handler::ProtocolHandler;
use lawn_protocol::protocol;
use lawn_protocol::protocol::{
    AuthenticateRequest, AuthenticateResponse, CapabilityResponse, ChannelID,
    ChannelMetadataNotification, ChannelMetadataNotificationKind, ChannelMetadataStatusKind,
    ClipboardChannelOperation, ClipboardChannelTarget, CreateChannelRequest, CreateChannelResponse,
    DeleteChannelRequest, DetachChannelSelectorRequest, Empty, MessageKind, PartialContinueRequest,
    PollChannelFlags, PollChannelRequest, PollChannelResponse, ReadChannelRequest,
    ReadChannelResponse, ResponseValue, VersionRequest, WriteChannelRequest, WriteChannelResponse,
};
use num_traits::FromPrimitive;
use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use serde::{de::DeserializeOwned, Serialize};
use serde_cbor::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::signal::unix::SignalKind;
use tokio::sync::mpsc::channel;
use tokio::sync::Mutex;
use tokio::task::{JoinHandle, JoinSet};

pub(crate) struct SignalHandler {
    logger: Arc<LoggerImpl>,
    handler: Arc<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>>,
    ttycfg: Arc<Mutex<TTYConfig>>,
}

impl SignalHandler {
    fn new(
        logger: Arc<LoggerImpl>,
        handler: Arc<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>>,
        ttycfg: Arc<Mutex<TTYConfig>>,
    ) -> Self {
        Self {
            logger,
            handler,
            ttycfg,
        }
    }

    async fn run_terminal_signals(&self) {
        let sigs = [
            SignalKind::terminate(),
            SignalKind::quit(),
            SignalKind::hangup(),
            SignalKind::interrupt(),
        ];
        let mut set = JoinSet::new();
        for sig in sigs {
            let exit_status = sig.as_raw_value() + 128;
            let ttycfg = self.ttycfg.clone();
            set.spawn(async move {
                if let Ok(mut s) = tokio::signal::unix::signal(sig) {
                    if s.recv().await.is_some() {
                        let s = ttycfg.lock().await;
                        let _ = s.tty.set_tty(s.fd.as_raw_fd(), true);
                        std::process::exit(exit_status);
                    }
                }
            });
        }
        loop {
            if set.join_next().await.is_none() {
                break;
            }
        }
    }

    async fn run_winch_signals(&self, id: ChannelID) {
        if let Ok(mut sig) = tokio::signal::unix::signal(SignalKind::window_change()) {
            while sig.recv().await.is_some() {
                let s = self.ttycfg.lock().await;
                if let Ok(tty) = TTYSettings::from_tty(self.logger.clone(), s.fd.as_raw_fd()) {
                    let size = tty.as_size();
                    let notification = protocol::ChannelMetadataNotificationTyped {
                        id,
                        kind: ChannelMetadataNotificationKind::TerminalWindowChange as u32,
                        status: None,
                        status_kind: None,
                        meta: Some(size),
                    };
                    let _ = self
                        .handler
                        .send_message::<_, Empty, Empty>(
                            MessageKind::ChannelMetadataNotification,
                            &notification,
                            None,
                        )
                        .await;
                }
            }
        }
    }
}

pub(crate) struct TTYConfig {
    fd: OwnedFd,
    tty: TTYSettings,
    selectors: Vec<u32>,
}

pub struct Connection {
    config: Arc<Config>,
    path: Option<PathBuf>,
    handler: Arc<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>>,
    capabilities: tokio::sync::RwLock<BTreeSet<protocol::Capability>>,
}

impl Connection {
    pub fn new(
        config: Arc<Config>,
        path: Option<&Path>,
        socket: UnixStream,
        synchronous: bool,
    ) -> Arc<Self> {
        let logger = config.logger();
        let cfg = Arc::new(lawn_protocol::config::Config::new(false, logger));
        let (sread, swrite) = socket.into_split();
        let handler = Arc::new(ProtocolHandler::new(cfg, sread, swrite, synchronous));
        Arc::new(Self {
            config,
            path: path.map(|p| p.into()),
            handler,
            capabilities: tokio::sync::RwLock::new(BTreeSet::new()),
        })
    }

    pub(crate) fn handler(&self) -> Arc<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>> {
        self.handler.clone()
    }

    pub(crate) fn config(&self) -> Arc<Config> {
        self.config.clone()
    }

    pub async fn ping(&self) -> Result<(), Error> {
        self.handler
            .send_message_simple::<Empty, Empty>(MessageKind::Ping, Some(true))
            .await?;
        Ok(())
    }

    pub async fn capability(&self) -> Result<CapabilityResponse, Error> {
        match self
            .handler
            .send_message_simple::<_, Empty>(MessageKind::Capability, Some(true))
            .await?
        {
            Some(ResponseValue::Success(resp)) => Ok(resp),
            Some(ResponseValue::Continuation(_)) => {
                Err(Error::new(ErrorKind::UnexpectedContinuation))
            }
            None => Err(Error::new(ErrorKind::MissingResponse)),
        }
    }

    #[allow(clippy::mutable_key_type)]
    pub async fn set_capabilities(&self, set: BTreeSet<protocol::Capability>) {
        let mut g = self.capabilities.write().await;
        *g = set;
    }

    #[allow(clippy::mutable_key_type)]
    pub async fn negotiate_default_version(&self) -> Result<CapabilityResponse, Error> {
        let resp: CapabilityResponse = match self
            .handler
            .send_message_simple::<_, Empty>(MessageKind::Capability, Some(true))
            .await?
        {
            Some(ResponseValue::Success(resp)) => resp,
            Some(ResponseValue::Continuation(_)) => {
                return Err(Error::new(ErrorKind::UnexpectedContinuation))
            }
            None => return Err(Error::new(ErrorKind::MissingResponse)),
        };
        let ours = self.config.capabilities();
        let theirs: BTreeSet<protocol::Capability> = resp
            .capabilities
            .iter()
            .cloned()
            .map(|c| c.into())
            .collect();
        let intersection: Vec<_> = ours
            .intersection(&theirs)
            .map(|x| (*x).clone().into())
            .collect();
        trace!(
            self.config.logger(),
            "client: version: versions {:?} ours {:?} theirs {:?} intersection {:?}",
            resp.version,
            ours,
            theirs,
            intersection
        );
        let req = VersionRequest {
            version: 0,
            enable: intersection.clone(),
            id: None,
            user_agent: Some(crate::config::VERSION.into()),
        };
        self.handler
            .send_message::<_, Empty, Empty>(MessageKind::Version, &req, Some(true))
            .await?;
        let mut g = self.capabilities.write().await;
        *g = intersection.iter().cloned().map(|x| x.into()).collect();
        Ok(resp)
    }

    pub async fn auth_external(&self) -> Result<AuthenticateResponse, Error> {
        let req = AuthenticateRequest {
            last_id: None,
            method: "EXTERNAL".into(),
            message: None,
        };
        match self
            .handler
            .send_message::<_, _, Empty>(MessageKind::Authenticate, &req, Some(true))
            .await?
        {
            Some(ResponseValue::Success(resp)) => Ok(resp),
            Some(ResponseValue::Continuation(_)) => {
                Err(Error::new(ErrorKind::UnexpectedContinuation))
            }
            None => Err(Error::new(ErrorKind::MissingResponse)),
        }
    }

    pub async fn send_message<T: Serialize, U: DeserializeOwned, V: DeserializeOwned>(
        &self,
        message: MessageKind,
        body: Option<T>,
    ) -> Result<Option<ResponseValue<U, V>>, Error> {
        let resp = match body {
            Some(body) => {
                self.handler
                    .send_message(message, &body, Some(true))
                    .await?
            }
            None => {
                self.handler
                    .send_message_simple(message, Some(true))
                    .await?
            }
        };
        Ok(resp)
    }

    pub async fn send_message_with_id<T: Serialize, U: DeserializeOwned, V: DeserializeOwned>(
        &self,
        message: MessageKind,
        body: Option<T>,
    ) -> Result<(u32, Option<ResponseValue<U, V>>), Error> {
        let resp = match body {
            Some(body) => {
                self.handler
                    .send_message_with_id(message, &body, Some(true))
                    .await?
            }
            None => {
                self.handler
                    .send_message_simple_with_id(message, Some(true))
                    .await?
            }
        };
        Ok(resp)
    }

    pub async fn send_message_simple<T: Serialize, U: DeserializeOwned>(
        &self,
        message: MessageKind,
        body: Option<T>,
    ) -> Result<Option<U>, Error> {
        let resp = match body {
            Some(body) => {
                self.handler
                    .send_message::<_, _, Empty>(message, &body, Some(true))
                    .await?
            }
            None => {
                self.handler
                    .send_message_simple(message, Some(true))
                    .await?
            }
        };
        match resp {
            Some(ResponseValue::Success(x)) => Ok(Some(x)),
            Some(ResponseValue::Continuation(..)) => {
                Err(Error::new(ErrorKind::UnexpectedContinuation))
            }
            None => Ok(None),
        }
    }

    pub async fn send_message_simple_with_id<T: Serialize, U: DeserializeOwned>(
        &self,
        message: MessageKind,
        body: Option<T>,
    ) -> Result<(u32, Option<U>), Error> {
        let resp = match body {
            Some(body) => {
                self.handler
                    .send_message_with_id::<_, _, Empty>(message, &body, Some(true))
                    .await?
            }
            None => {
                self.handler
                    .send_message_simple_with_id(message, Some(true))
                    .await?
            }
        };
        match resp {
            (id, Some(ResponseValue::Success(x))) => Ok((id, Some(x))),
            (_, Some(ResponseValue::Continuation(..))) => {
                Err(Error::new(ErrorKind::UnexpectedContinuation))
            }
            (id, None) => Ok((id, None)),
        }
    }

    pub async fn send_pagination_message<
        I,
        T: Serialize,
        U: DeserializeOwned + IntoIterator<Item = I>,
    >(
        &self,
        message: MessageKind,
        body: Option<T>,
    ) -> Result<Option<Vec<I>>, Error> {
        let mut resp = match body {
            Some(body) => self.handler.send_message(message, &body, Some(true)).await,
            None => self.handler.send_message_simple(message, Some(true)).await,
        };
        let mut data = vec![];
        let mut id = None;
        loop {
            let msgid = match resp {
                Ok(Some(ResponseValue::Success(v))) => {
                    let v: U = v;
                    data.extend(v);
                    return Ok(Some(data));
                }
                Ok(Some(ResponseValue::Continuation((id, v)))) => {
                    let v: U = v;
                    data.extend(v);
                    id
                }
                Ok(None) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            let reqid = match id {
                Some(id) => id,
                None => {
                    id = Some(msgid);
                    msgid
                }
            };
            let req = PartialContinueRequest {
                kind: message as u32,
                id: reqid,
            };
            resp = self
                .handler
                .send_message(MessageKind::Continue, &req, Some(true))
                .await;
        }
    }

    pub async fn read_template_context<T: DeserializeOwned>(
        &self,
        id: Bytes,
    ) -> Result<
        Option<(
            Option<String>,
            protocol::TemplateServerContextBodyWithBody<T>,
        )>,
        Error,
    > {
        let req = protocol::ReadServerContextRequest {
            kind: "template".into(),
            id: Some(id),
            meta: None,
        };
        match self
            .send_message_simple::<_, protocol::ReadServerContextResponseWithBody<
                protocol::TemplateServerContextBodyWithBody<T>,
            >>(MessageKind::ReadServerContext, Some(&req))
            .await
        {
            Ok(Some(resp)) => match resp.body {
                Some(body) => {
                    if let Some(serde_cbor::Value::Text(kind)) = resp
                        .meta
                        .and_then(|mut m| m.remove(b"template-type".as_slice()))
                    {
                        Ok(Some((Some(kind), body)))
                    } else {
                        Ok(Some((None, body)))
                    }
                }
                None => Err(Error::new(ErrorKind::MissingResponse)),
            },
            Ok(None) => Err(Error::new(ErrorKind::MissingResponse)),
            Err(e) => match protocol::Error::try_from(e) {
                Ok(protocol::Error {
                    code: protocol::ResponseCode::NotFound,
                    ..
                }) => Ok(None),
                Ok(e) => Err(handler::Error::ProtocolError(e).into()),
                Err(e) => Err(e.0),
            },
        }
    }

    pub async fn run_clipboard<
        I: AsyncReadExt + Unpin + Send + 'static,
        O: AsyncWriteExt + Unpin + Send + 'static,
    >(
        self: Arc<Self>,
        stdin: I,
        stdout: O,
        stdout_isatty: bool,
        op: ClipboardChannelOperation,
        target: Option<ClipboardChannelTarget>,
    ) -> Result<i32, Error> {
        let devnull = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .await
            .unwrap();
        let stderr = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .await
            .unwrap();
        let id = self.create_clipboard_channel(op, target).await?;
        match op {
            ClipboardChannelOperation::Copy => {
                self.run_channel(stdin, devnull, stderr, !stdout_isatty, id, None)
                    .await
            }
            ClipboardChannelOperation::Paste => {
                self.run_channel(devnull, stdout, stderr, !stdout_isatty, id, None)
                    .await
            }
        }
    }

    pub async fn run_9p<
        I: AsyncReadExt + Unpin + Send + 'static,
        O: AsyncWriteExt + Unpin + Send + 'static,
    >(
        self: Arc<Self>,
        stdin: I,
        stdout: O,
        target: Bytes,
    ) -> Result<i32, Error> {
        let devnull = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .await
            .unwrap();
        let id = self.create_9p_channel(target).await?;
        self.run_channel(stdin, stdout, devnull, false, id, None)
            .await
    }

    pub async fn run_sftp<
        I: AsyncReadExt + Unpin + Send + 'static,
        O: AsyncWriteExt + Unpin + Send + 'static,
    >(
        self: Arc<Self>,
        stdin: I,
        stdout: O,
        target: Bytes,
    ) -> Result<i32, Error> {
        let devnull = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .await
            .unwrap();
        let id = self.create_sftp_channel(target).await?;
        self.run_channel(stdin, stdout, devnull, false, id, None)
            .await
    }

    pub async fn run_command<
        I: AsyncReadExt + Unpin + Send + 'static,
        O: AsyncWriteExt + Unpin + Send + 'static,
        E: AsyncWriteExt + Unpin + Send + 'static,
    >(
        self: Arc<Self>,
        args: &[Bytes],
        stdin: I,
        stdout: O,
        stderr: E,
        stdout_isatty: bool,
    ) -> Result<i32, Error> {
        let id = self.create_command_channel(args, None).await?;
        self.run_channel(stdin, stdout, stderr, !stdout_isatty, id, None)
            .await
    }

    pub async fn run_command_fd<
        I: AsyncReadExt + AsFd + Unpin + Send + 'static,
        O: AsyncWriteExt + AsFd + Unpin + Send + 'static,
        E: AsyncWriteExt + AsFd + Unpin + Send + 'static,
    >(
        self: Arc<Self>,
        args: &[Bytes],
        stdin: I,
        stdout: O,
        stderr: E,
    ) -> Result<i32, Error> {
        let logger = self.config.logger();
        let fds = &[stdin.as_fd(), stdout.as_fd(), stderr.as_fd()];
        let mut tty = None;
        let mut selectors = vec![];
        for (i, fd) in fds.iter().enumerate() {
            if rustix::termios::isatty(fd) {
                trace!(
                    logger,
                    "found selector {} (fd {}) is a TTY",
                    i,
                    fd.as_raw_fd()
                );
                if tty.is_none() {
                    let ttyfd = rustix::io::dup(fd)
                        .map_err(|e| Error::new_with_cause(ErrorKind::TTYError, e))?;
                    trace!(
                        logger,
                        "chose selector {} (fd {:?}) as our TTY (verified {})",
                        i,
                        &ttyfd,
                        rustix::termios::isatty(&ttyfd)
                    );
                    tty = Some(ttyfd);
                }
            }
            selectors.push(i as u32);
        }
        let has_tty = self
            .capabilities
            .read()
            .await
            .contains(&protocol::Capability::ChannelCommandTTY);
        let (settings, sh) = if !has_tty {
            trace!(
                logger,
                "skipping TTY because the remote side does not support it"
            );
            (None, None)
        } else if let Some(tty) = tty {
            trace!(logger, "configuring TTY settings on {}", tty.as_raw_fd());
            let ttysettings = TTYSettings::from_tty(logger.clone(), tty.as_raw_fd())
                .map_err(|e| Error::new_with_cause(ErrorKind::TTYError, e))?;
            let mut raw = ttysettings.clone();
            raw.set_raw();
            raw.set_tty(tty.as_raw_fd(), false)
                .map_err(|e| Error::new_with_cause(ErrorKind::TTYError, e))?;
            let ttycfg = Arc::new(Mutex::new(TTYConfig {
                fd: tty,
                tty: ttysettings,
                selectors,
            }));
            let ttycfg2 = ttycfg.clone();
            (
                Some(ttycfg),
                Some(SignalHandler::new(
                    logger.clone(),
                    self.handler.clone(),
                    ttycfg2,
                )),
            )
        } else {
            (None, None)
        };
        let func = async {
            let id = self.create_command_channel(args, settings.clone()).await?;
            let stdout_isatty = rustix::termios::isatty(&stdout);
            self.run_channel(
                stdin,
                stdout,
                stderr,
                !(stdout_isatty || settings.is_some()),
                id,
                sh,
            )
            .await
        };
        let res = func.await;
        if let Some(settings) = settings {
            let s = settings.lock().await;
            let res = s.tty.set_tty(s.fd.as_raw_fd(), true);
            trace!(logger, "reset TTY settings: {:?}", res);
        }
        res
    }

    async fn run_channel<
        I: AsyncReadExt + Unpin + Send + 'static,
        O: AsyncWriteExt + Unpin + Send + 'static,
        E: AsyncWriteExt + Unpin + Send + 'static,
    >(
        self: Arc<Self>,
        stdin: I,
        stdout: O,
        stderr: E,
        complete: bool,
        id: ChannelID,
        sh: Option<SignalHandler>,
    ) -> Result<i32, Error> {
        let rhandler = self.handler.clone();
        let (finaltx, mut finalrx) = tokio::sync::mpsc::channel(1);
        let logger = self.config.logger();
        tokio::spawn(async move {
            loop {
                let msg = rhandler.recv().await;
                trace!(logger, "received packet");
                if let Ok(Some(msg)) = msg {
                    trace!(logger, "received async response");
                    if let Some(code) = Self::handle_async_run_message(&rhandler, &msg) {
                        trace!(logger, "sending final message");
                        finaltx.send(Ok(code)).await.unwrap();
                    }
                }
            }
        });
        self.clone().io_channel_write_task(id, 0, stdin);
        let stdout_task = self.clone().io_channel_read_task(id, 1, complete, stdout);
        let stderr_task = self.clone().io_channel_read_task(id, 2, false, stderr);
        let signal_task = self.clone().channel_signal_task(id, sh);
        let res = finalrx.recv().await;
        let _ = tokio::join!(stdout_task, stderr_task);
        signal_task.abort_handle().abort();
        let _ = self.delete_channel(id).await;
        trace!(self.config.logger(), "returning value");
        res.unwrap()
    }

    pub(crate) fn channel_signal_task(
        self: Arc<Self>,
        id: ChannelID,
        sh: Option<SignalHandler>,
    ) -> JoinHandle<()> {
        tokio::task::spawn(async move {
            if let Some(sh) = sh {
                loop {
                    tokio::select! {
                        _ = sh.run_terminal_signals() => {
                            return;
                        }
                        _ = sh.run_winch_signals(id) => continue,
                    }
                }
            }
        })
    }

    pub(crate) fn io_channel_write_task<R: AsyncReadExt + Unpin + Send + 'static>(
        self: Arc<Self>,
        id: ChannelID,
        selector: u32,
        r: R,
    ) -> JoinHandle<Result<u64, Error>> {
        tokio::task::spawn(async move {
            let r = self.clone().write_copy_command_fd(id, selector, r).await;
            self.detach_channel_selector(id, selector).await;
            r
        })
    }

    pub(crate) fn io_channel_read_task<W: AsyncWriteExt + Unpin + Send + 'static>(
        self: Arc<Self>,
        id: ChannelID,
        selector: u32,
        complete: bool,
        w: W,
    ) -> JoinHandle<Result<u64, Error>> {
        tokio::task::spawn(async move {
            let r = self
                .clone()
                .read_copy_command_fd(id, selector, complete, w)
                .await;
            self.detach_channel_selector(id, selector).await;
            r
        })
    }

    async fn write_copy_command_fd<R: AsyncReadExt + Unpin + Send + 'static>(
        self: Arc<Self>,
        id: ChannelID,
        selector: u32,
        r: R,
    ) -> Result<u64, Error> {
        let mut r = r;
        let (intx, mut inrx) = channel::<Result<Bytes, Error>>(20);
        let (outtx, mut outrx) = channel(20);
        let (msgtx, msgrx) = channel(20);
        let (resptx, mut resprx) = channel(20);
        let handler = self.handler.clone();
        let config = self.config.clone();
        let logger = self.config.logger();
        let blocking = {
            let capa = self.capabilities.read().await;
            if capa.contains(&protocol::Capability::ChannelBlockingIO) {
                Some(true)
            } else {
                None
            }
        };
        let msgproc = tokio::spawn(async move {
            handler
                .send_messages_from_channel::<WriteChannelRequest, WriteChannelResponse, Empty>(
                    MessageKind::WriteChannel,
                    msgrx,
                    resptx,
                )
                .await;
        });
        let outtx2 = outtx.clone();
        let sender = tokio::spawn(async move {
            if blocking != Some(true) {
                return;
            }
            while let Some(msg) = resprx.recv().await {
                let resp = match msg {
                    Ok(Some(ResponseValue::Success(resp))) => Ok(resp.count),
                    Ok(Some(ResponseValue::Continuation(_))) => {
                        Err(Error::new(ErrorKind::UnexpectedContinuation))
                    }
                    Ok(None) => Err(Error::new(ErrorKind::MissingResponse)),
                    Err(e) => Err(e.into()),
                };
                if outtx2.send(resp).await.is_err() {
                    return;
                }
            }
        });
        let writer = tokio::spawn(async move {
            let mut total = 0u64;
            while let Some(buf) = inrx.recv().await {
                let buf = match buf {
                    Ok(buf) => buf,
                    Err(e) => {
                        let _ = outtx.send(Err(e)).await;
                        return;
                    }
                };
                if blocking == Some(true) {
                    let req = WriteChannelRequest {
                        id,
                        selector,
                        bytes: buf.clone(),
                        stream_sync: Some(total),
                        blocking,
                    };
                    trace!(
                        logger,
                        "blocking channel write: offset {}; {} bytes to write; new offset {}",
                        total,
                        buf.len(),
                        total + (buf.len() as u64),
                    );
                    total += buf.len() as u64;
                    if msgtx.send(req).await.is_err() {
                        return;
                    }
                } else {
                    let mut off = 0;
                    while off < buf.len() {
                        trace!(
                            logger,
                            "non-blocking channel write: offset {} of {} bytes",
                            off,
                            buf.len()
                        );
                        match self
                            .clone()
                            .write_channel(id, selector, buf.slice(off..))
                            .await
                        {
                            Ok(written) => {
                                off += written as usize;
                                trace!(
                                    logger,
                                    "non-blocking channel write: wrote {} bytes; offset {}",
                                    written,
                                    off
                                );
                            }
                            Err(e) => match io::Error::try_from(e) {
                                Ok(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    let mut selectors = BTreeMap::new();
                                    selectors.insert(
                                        1,
                                        PollChannelFlags::Output | PollChannelFlags::Hangup,
                                    );
                                    let _ = Self::poll_channel(
                                        self.config.clone(),
                                        self.handler.clone(),
                                        id,
                                        &selectors,
                                    )
                                    .await;
                                    continue;
                                }
                                Ok(e) => {
                                    let _ = outtx
                                        .send(Err(
                                            handler::Error::from(protocol::Error::from(e)).into()
                                        ))
                                        .await;
                                    return;
                                }
                                Err(e) => {
                                    let _ = outtx.send(Err(e.0)).await;
                                    return;
                                }
                            },
                        }
                    }
                    if outtx.send(Ok(buf.len() as u64)).await.is_err() {
                        return;
                    }
                }
            }
        });
        let reader = tokio::spawn(async move {
            loop {
                let mut buf = BytesMut::with_capacity(65536);
                match r.read_buf(&mut buf).await {
                    Ok(0) => return,
                    Ok(sz) => sz,
                    Err(e) => {
                        let _ = intx
                            .send(Err(handler::Error::from(protocol::Error::from(e)).into()))
                            .await;
                        return;
                    }
                };
                let buf: Bytes = buf.into();
                let _ = intx.send(Ok(buf)).await;
            }
        });
        let logger = config.logger();
        let mut total = 0u64;
        while let Some(r) = outrx.recv().await {
            match r {
                Ok(n) => {
                    trace!(logger, "channel write output ok: {} bytes", n);
                    total += n;
                }
                Err(e) => {
                    reader.abort();
                    writer.abort();
                    msgproc.abort();
                    sender.abort();
                    return Err(e);
                }
            }
        }
        Ok(total)
    }

    async fn read_copy_command_fd<W: AsyncWriteExt + Unpin>(
        self: Arc<Self>,
        id: ChannelID,
        selector: u32,
        complete: bool,
        w: W,
    ) -> Result<u64, Error> {
        let mut w = w;
        let mut total = 0u64;
        loop {
            let data = match self.clone().read_channel(id, selector, complete).await {
                Ok(data) if data.is_empty() => return Ok(total),
                Ok(data) => data,
                Err(e) => match io::Error::try_from(e) {
                    Ok(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        let mut selectors = BTreeMap::new();
                        selectors.insert(1, PollChannelFlags::Output | PollChannelFlags::Hangup);
                        let _ = Self::poll_channel(
                            self.config.clone(),
                            self.handler.clone(),
                            id,
                            &selectors,
                        )
                        .await;
                        continue;
                    }
                    Ok(e) => return Err(handler::Error::from(protocol::Error::from(e)).into()),
                    Err(e) => return Err(e.0),
                },
            };
            match w.write_all(&data).await {
                Ok(()) => {
                    total += data.len() as u64;
                }
                Err(e) => return Err(handler::Error::from(protocol::Error::from(e)).into()),
            };
            match w.flush().await {
                Ok(()) => (),
                Err(e) => return Err(handler::Error::from(protocol::Error::from(e)).into()),
            }
        }
    }

    pub(crate) fn handle_async_run_message(
        handler: &ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>,
        msg: &protocol::Message,
    ) -> Option<i32> {
        let s = handler.serializer();
        match MessageKind::from_u32(msg.kind) {
            // TODO: signal this more gracefully.
            Some(MessageKind::CloseAlert) => Some(255),
            Some(MessageKind::ChannelMetadataNotification) => {
                if let Ok(Some(r)) = s.deserialize_message_typed::<ChannelMetadataNotification>(msg)
                {
                    if r.kind != ChannelMetadataNotificationKind::WaitStatus as u32 {
                        return None;
                    }
                    return match r.status_kind.and_then(ChannelMetadataStatusKind::from_u32) {
                        Some(ChannelMetadataStatusKind::Exited) => r.status.map(|x| x as i32),
                        // TODO: actually raise a signal somewhere
                        Some(ChannelMetadataStatusKind::Signalled)
                        | Some(ChannelMetadataStatusKind::SignalledWithCore) => {
                            r.status.map(|x| x as i32 + 128)
                        }
                        _ => None,
                    };
                }
                None
            }
            _ => None,
        }
    }

    async fn poll_channel(
        config: Arc<Config>,
        handler: Arc<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>>,
        id: ChannelID,
        selectors: &BTreeMap<u32, protocol::PollChannelFlags>,
    ) -> Result<BTreeMap<u32, u64>, Error> {
        let logger = config.logger();
        let wanted = selectors.values().cloned().map(|f| f.bits()).collect();
        let fds = selectors.keys().cloned().collect();
        let req = PollChannelRequest {
            id,
            selectors: fds,
            milliseconds: Some(10 * 1000),
            wanted: Some(wanted),
        };
        trace!(logger, "channel {}: poll: selectors: {:?}", id, selectors);
        let resp = match handler
            .send_message::<_, _, Empty>(MessageKind::PollChannel, &req, Some(false))
            .await?
        {
            Some(resp) => resp,
            None => return Err(Error::new(ErrorKind::MissingResponse)),
        };
        let resp: PollChannelResponse = match resp {
            ResponseValue::Success(resp) => resp,
            ResponseValue::Continuation(_) => {
                return Err(Error::new(ErrorKind::UnexpectedContinuation))
            }
        };
        trace!(logger, "channel {}: poll: response", id);
        Ok(resp.selectors)
    }

    async fn read_channel(
        self: Arc<Self>,
        id: ChannelID,
        selector: u32,
        complete: bool,
    ) -> Result<Bytes, Error> {
        let (blocking, complete) = {
            let capa = self.capabilities.read().await;
            if capa.contains(&protocol::Capability::ChannelBlockingIO) {
                (Some(true), complete)
            } else {
                (None, false)
            }
        };
        let req = ReadChannelRequest {
            id,
            selector,
            count: 65536,
            stream_sync: None,
            blocking,
            complete,
        };
        let resp: ReadChannelResponse = match self
            .handler
            .send_message::<_, _, Empty>(MessageKind::ReadChannel, &req, Some(false))
            .await?
        {
            Some(ResponseValue::Success(resp)) => resp,
            Some(ResponseValue::Continuation(_)) => {
                return Err(Error::new(ErrorKind::UnexpectedContinuation))
            }
            None => return Err(Error::new(ErrorKind::MissingResponse)),
        };
        Ok(resp.bytes)
    }

    async fn write_channel(
        self: Arc<Self>,
        id: ChannelID,
        selector: u32,
        data: Bytes,
    ) -> Result<u64, Error> {
        let blocking = {
            let capa = self.capabilities.read().await;
            if capa.contains(&protocol::Capability::ChannelBlockingIO) {
                Some(true)
            } else {
                None
            }
        };
        let req = WriteChannelRequest {
            id,
            selector,
            bytes: data,
            stream_sync: None,
            blocking,
        };
        let resp: WriteChannelResponse = match self
            .handler
            .send_message::<_, _, Empty>(MessageKind::WriteChannel, &req, Some(false))
            .await?
        {
            Some(ResponseValue::Success(resp)) => resp,
            Some(ResponseValue::Continuation(_)) => {
                return Err(Error::new(ErrorKind::UnexpectedContinuation))
            }
            None => return Err(Error::new(ErrorKind::MissingResponse)),
        };
        Ok(resp.count)
    }

    pub(crate) async fn detach_channel_selector(self: Arc<Self>, id: ChannelID, selector: u32) {
        let req = DetachChannelSelectorRequest { id, selector };
        let res = self
            .handler
            .send_message::<_, Empty, Empty>(MessageKind::DetachChannelSelector, &req, Some(false))
            .await;
        trace!(
            self.config.logger(),
            "channel {}: {}: detach selector: {:?}",
            id,
            selector,
            res
        );
    }

    pub(crate) async fn create_command_channel(
        &self,
        args: &[Bytes],
        tty: Option<Arc<Mutex<TTYConfig>>>,
    ) -> Result<ChannelID, Error> {
        let logger = self.config.logger();
        let config = self.config.clone();
        let env = config.env_vars().clone();
        let term = match env.get(b"TERM" as &[u8]) {
            Some(b) => b.clone(),
            None => Bytes::from(b"dumb" as &[u8]),
        };
        let meta = match tty {
            Some(tty) => {
                let cfg = tty.lock().await;
                let mut meta: BTreeMap<Bytes, Value> = BTreeMap::new();
                meta.insert(Bytes::from(b"tty" as &[u8]), Value::Bool(true));
                meta.insert(
                    Bytes::from(b"tty-selectors" as &[u8]),
                    Value::Array(
                        cfg.selectors
                            .iter()
                            .map(|s| Value::Integer(*s as i128))
                            .collect(),
                    ),
                );
                meta.insert(
                    Bytes::from(b"modes" as &[u8]),
                    Value::Map(cfg.tty.to_cbor_map()),
                );
                meta.insert(Bytes::from(b"term" as &[u8]), Value::Bytes(term.to_vec()));
                let size = cfg.tty.as_size();
                let entries: &[(&[u8], u32)] = &[
                    (b"height-cells", size.height_cells),
                    (b"width-cells", size.width_cells),
                    (b"height-pixels", size.height_pixels),
                    (b"width-pixels", size.width_pixels),
                ];
                for (name, value) in entries {
                    meta.insert(Bytes::from(*name), Value::Integer(*value as i128));
                }
                trace!(logger, "setting TTY configuration for channel: {:?}", meta);
                Some(meta)
            }
            None => None,
        };
        let req = CreateChannelRequest {
            kind: (b"command" as &'static [u8]).into(),
            kind_args: None,
            args: Some(args.into()),
            env: Some(env),
            meta,
            selectors: vec![0, 1, 2],
        };
        let resp: CreateChannelResponse = match self
            .handler
            .send_message::<_, _, Empty>(MessageKind::CreateChannel, &req, Some(true))
            .await?
        {
            Some(ResponseValue::Success(resp)) => resp,
            Some(ResponseValue::Continuation(_)) => {
                return Err(Error::new(ErrorKind::UnexpectedContinuation))
            }
            None => return Err(Error::new(ErrorKind::MissingResponse)),
        };
        Ok(resp.id)
    }

    #[allow(clippy::mutable_key_type)]
    async fn create_clipboard_channel(
        &self,
        op: ClipboardChannelOperation,
        target: Option<ClipboardChannelTarget>,
    ) -> Result<ChannelID, Error> {
        let mut meta = BTreeMap::new();
        let selectors = match op {
            ClipboardChannelOperation::Copy => {
                meta.insert(
                    (b"operation" as &'static [u8]).into(),
                    Value::Text("copy".into()),
                );
                vec![0]
            }
            ClipboardChannelOperation::Paste => {
                meta.insert(
                    (b"operation" as &'static [u8]).into(),
                    Value::Text("paste".into()),
                );
                vec![1]
            }
        };
        match target {
            Some(ClipboardChannelTarget::Primary) => meta.insert(
                (b"target" as &'static [u8]).into(),
                Value::Text("primary".into()),
            ),
            Some(ClipboardChannelTarget::Clipboard) => meta.insert(
                (b"target" as &'static [u8]).into(),
                Value::Text("clipboard".into()),
            ),
            None => None,
        };
        let req = CreateChannelRequest {
            kind: (b"clipboard" as &'static [u8]).into(),
            kind_args: None,
            args: None,
            env: None,
            meta: Some(meta),
            selectors,
        };
        let resp: CreateChannelResponse = match self
            .handler
            .send_message::<_, _, Empty>(MessageKind::CreateChannel, &req, Some(true))
            .await?
        {
            Some(ResponseValue::Success(resp)) => resp,
            Some(ResponseValue::Continuation(_)) => {
                return Err(Error::new(ErrorKind::UnexpectedContinuation))
            }
            None => return Err(Error::new(ErrorKind::MissingResponse)),
        };
        Ok(resp.id)
    }

    async fn create_9p_channel(&self, target: Bytes) -> Result<ChannelID, Error> {
        self.create_fs_channel(target, b"9p").await
    }

    async fn create_sftp_channel(&self, target: Bytes) -> Result<ChannelID, Error> {
        self.create_fs_channel(target, b"sftp").await
    }

    async fn create_fs_channel(&self, target: Bytes, kind: &[u8]) -> Result<ChannelID, Error> {
        let req = CreateChannelRequest {
            kind: kind.to_owned().into(),
            kind_args: None,
            args: Some(vec![target]),
            env: Some(self.config.env_vars().clone()),
            meta: None,
            selectors: vec![0, 1],
        };
        let resp: CreateChannelResponse = match self
            .handler
            .send_message::<_, _, Empty>(MessageKind::CreateChannel, &req, Some(true))
            .await?
        {
            Some(ResponseValue::Success(resp)) => resp,
            Some(ResponseValue::Continuation(_)) => {
                return Err(Error::new(ErrorKind::UnexpectedContinuation))
            }
            None => return Err(Error::new(ErrorKind::MissingResponse)),
        };
        Ok(resp.id)
    }

    async fn delete_channel(&self, id: ChannelID) -> Result<(), Error> {
        let req = DeleteChannelRequest {
            id,
            termination: None,
        };
        self.handler
            .send_message::<_, Empty, Empty>(MessageKind::DeleteChannel, &req, Some(false))
            .await?;
        Ok(())
    }
}

pub struct Client {
    config: Arc<Config>,
}

impl Client {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    pub async fn connect_to_socket(
        &self,
        stream: std::os::unix::net::UnixStream,
        synchronous: bool,
    ) -> Result<Arc<Connection>, Error> {
        let _ = stream.set_nonblocking(true);
        match UnixStream::from_std(stream) {
            Ok(stream) => Ok(Connection::new(
                self.config.clone(),
                None,
                stream,
                synchronous,
            )),
            Err(_) => {
                self.config
                    .logger()
                    .error("unable to connect to existing socket");
                Err(Error::new(ErrorKind::SocketConnectionFailure))
            }
        }
    }

    pub async fn connect<I: AsRef<Path>>(
        &self,
        location: I,
        synchronous: bool,
    ) -> Result<Arc<Connection>, Error> {
        match UnixStream::connect(location.as_ref()).await {
            Ok(stream) => Ok(Connection::new(
                self.config.clone(),
                Some(location.as_ref()),
                stream,
                synchronous,
            )),
            Err(_) => {
                self.config.logger().error(&format!(
                    "unable to connect to socket \"{}\"",
                    escape(path(location.as_ref()))
                ));
                Err(Error::new(ErrorKind::SocketConnectionFailure))
            }
        }
    }
}
