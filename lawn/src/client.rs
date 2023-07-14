#![allow(dead_code)]

use crate::config::{self, Config};
use crate::encoding::{escape, path};
use crate::error::{Error, ErrorKind};
use bytes::Bytes;
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
use serde::{de::DeserializeOwned, Serialize};
use serde_cbor::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::select;
use tokio::task::JoinHandle;
use tokio::time;

// TODO: std::task::ready is unstable until Rust 1.64.  This is an implementation of it until we
// can depend on it.
macro_rules! ready {
    ($expr:expr) => {{
        match $expr {
            std::task::Poll::Pending => return std::task::Poll::Pending,
            std::task::Poll::Ready(r) => r,
        }
    }};
}

#[derive(Clone)]
pub struct FDStatus {
    open: bool,
    last: bool,
    data: Option<Vec<u8>>,
}

impl FDStatus {
    /// Returns true if read_command_fd should be called again when draining this stream.
    fn needs_final_read(&self) -> bool {
        self.open && self.last
    }

    /// Returns true if read_command_fd should be called again when draining this stream.
    fn needs_final_write(&self) -> bool {
        self.open
    }

    /// Returns true if read_command_fd should be called again.
    fn needs_read(&self) -> bool {
        self.open && self.last
    }

    /// Returns true if write_command_fd should be called again.
    fn needs_write(&self) -> bool {
        self.open && self.last
    }

    fn closed() -> FDStatus {
        FDStatus {
            open: false,
            last: false,
            data: None,
        }
    }
}

impl Default for FDStatus {
    fn default() -> FDStatus {
        FDStatus {
            open: true,
            last: false,
            data: None,
        }
    }
}

pub struct Connection {
    config: Arc<Config>,
    path: Option<PathBuf>,
    handler: Arc<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>>,
}

impl Connection {
    pub fn new(
        config: Arc<Config>,
        path: Option<&Path>,
        socket: UnixStream,
        synchronous: bool,
    ) -> Self {
        let logger = config.logger();
        let cfg = Arc::new(lawn_protocol::config::Config::new(false, logger));
        let (sread, swrite) = socket.into_split();
        let handler = Arc::new(ProtocolHandler::new(cfg, sread, swrite, synchronous));
        Self {
            config,
            path: path.map(|p| p.into()),
            handler,
        }
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
            .filter_map(|c| c.try_into().ok())
            .collect();
        let intersection = ours
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
            enable: intersection,
            id: None,
            user_agent: Some(crate::config::VERSION.into()),
        };
        self.handler
            .send_message::<_, Empty, Empty>(MessageKind::Version, &req, Some(true))
            .await?;
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

    pub async fn run_clipboard<
        I: AsyncReadExt + Unpin + Send + 'static,
        O: AsyncWriteExt + Unpin + Send + 'static,
    >(
        &self,
        stdin: I,
        stdout: O,
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
                let mut fd_status = [FDStatus::default(), FDStatus::closed()];
                self.run_channel(stdin, devnull, stderr, id, &mut fd_status)
                    .await
            }
            ClipboardChannelOperation::Paste => {
                let mut fd_status = [FDStatus::closed(), FDStatus::default()];
                self.run_channel(devnull, stdout, stderr, id, &mut fd_status)
                    .await
            }
        }
    }

    pub async fn run_9p<
        I: AsyncReadExt + Unpin + Send + 'static,
        O: AsyncWriteExt + Unpin + Send + 'static,
    >(
        &self,
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
        let mut fd_status = [FDStatus::default(), FDStatus::default()];
        self.run_channel(stdin, stdout, devnull, id, &mut fd_status)
            .await
    }

    pub async fn run_sftp<
        I: AsyncReadExt + Unpin + Send + 'static,
        O: AsyncWriteExt + Unpin + Send + 'static,
    >(
        &self,
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
        let mut fd_status = [FDStatus::default(), FDStatus::default()];
        self.run_channel(stdin, stdout, devnull, id, &mut fd_status)
            .await
    }

    pub async fn run_command<
        I: AsyncReadExt + Unpin + Send + 'static,
        O: AsyncWriteExt + Unpin + Send + 'static,
        E: AsyncWriteExt + Unpin + Send + 'static,
    >(
        &self,
        args: &[Bytes],
        stdin: I,
        stdout: O,
        stderr: E,
    ) -> Result<i32, Error> {
        let id = self.create_command_channel(args).await?;
        let mut fd_status = [
            FDStatus::default(),
            FDStatus::default(),
            FDStatus::default(),
        ];
        self.run_channel(stdin, stdout, stderr, id, &mut fd_status)
            .await
    }

    async fn run_channel<
        I: AsyncReadExt + Unpin + Send + 'static,
        O: AsyncWriteExt + Unpin + Send + 'static,
        E: AsyncWriteExt + Unpin + Send + 'static,
    >(
        &self,
        stdin: I,
        stdout: O,
        stderr: E,
        id: ChannelID,
        _fd_status: &mut [FDStatus],
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
        let logger = self.config.logger();
        self.io_channel_write_task(id, 0, stdin);
        let stdout_task = self.io_channel_read_task(id, 1, stdout);
        let stderr_task = self.io_channel_read_task(id, 2, stderr);
        let res = finalrx.recv().await;
        let _ = tokio::join!(stdout_task, stderr_task,);
        let _ = self.delete_channel(id).await;
        trace!(logger, "returning value");
        res.unwrap()
    }

    fn io_channel_read_task<W: AsyncWriteExt + Unpin + Send + 'static>(
        &self,
        id: ChannelID,
        selector: u32,
        w: W,
    ) -> JoinHandle<Result<u64, io::Error>> {
        let logger = self.config.logger();
        let handler = self.handler.clone();
        let mut reader =
            ChannelReader::new(self.config.clone(), self.handler.clone(), id, selector);
        let mut w = w;
        tokio::task::spawn(async move {
            let r = tokio::io::copy(&mut reader, &mut w).await;
            trace!(logger, "client: {}: {}: finished read", id, selector);
            Self::detach_channel_selector_internal(logger.clone(), handler, id, selector).await;
            trace!(logger, "client: {}: {}: detached", id, selector);
            r
        })
    }

    fn io_channel_write_task<R: AsyncReadExt + Unpin + Send + 'static>(
        &self,
        id: ChannelID,
        selector: u32,
        r: R,
    ) -> JoinHandle<Result<u64, io::Error>> {
        let logger = self.config.logger();
        let handler = self.handler.clone();
        let mut writer =
            ChannelWriter::new(self.config.clone(), self.handler.clone(), id, selector);
        let mut r = r;
        tokio::task::spawn(async move {
            let r = tokio::io::copy(&mut r, &mut writer).await;
            trace!(logger, "client: {}: {}: finished write", id, selector);
            Self::detach_channel_selector_internal(logger.clone(), handler, id, selector).await;
            trace!(logger, "client: {}: {}: detached", id, selector);
            r
        })
    }

    fn handle_async_run_message(
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
        selectors: BTreeMap<u32, protocol::PollChannelFlags>,
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

    async fn write_command_fd<T: AsyncWriteExt + Unpin>(
        &self,
        id: ChannelID,
        selector: u32,
        st: &FDStatus,
        io: &mut T,
    ) -> FDStatus {
        let logger = self.config.logger();
        if !st.open {
            trace!(logger, "channel {}: closed selector {}", id, selector);
            return st.clone();
        }
        let read_data;
        let data: &[u8] = match &st.data {
            Some(data) if !data.is_empty() => data,
            Some(_) | None => {
                trace!(
                    logger,
                    "channel {}: {}: about to read from channel",
                    id,
                    selector
                );
                match self.read_channel(id, selector).await {
                    Ok(data) => {
                        trace!(
                            logger,
                            "channel {}: {}: read channel: {} bytes",
                            id,
                            selector,
                            data.len()
                        );
                        read_data = data;
                        &read_data
                    }
                    Err(e) => {
                        trace!(
                            logger,
                            "channel {}: {}: read channel: error {}",
                            id,
                            selector,
                            e
                        );
                        use std::error::Error;
                        if let Some(e) = e.source() {
                            if let Some(e) = e.downcast_ref::<protocol::Error>() {
                                let e: Result<std::io::Error, _> = e.clone().try_into();
                                if let Ok(e) = e {
                                    match e.kind() {
                                        std::io::ErrorKind::BrokenPipe => {
                                            return FDStatus {
                                                open: false,
                                                last: false,
                                                data: None,
                                            }
                                        }
                                        std::io::ErrorKind::WouldBlock => {
                                            return FDStatus {
                                                open: true,
                                                last: false,
                                                data: None,
                                            }
                                        }
                                        _ => return st.clone(),
                                    }
                                }
                            }
                        }
                        return FDStatus {
                            open: true,
                            last: false,
                            data: None,
                        };
                    }
                }
            }
        };
        if data.is_empty() {
            self.detach_channel_selector(id, selector).await;
            return FDStatus {
                open: false,
                last: false,
                data: None,
            };
        }
        trace!(
            logger,
            "channel {}: {}: about to write {} bytes to fd",
            id,
            selector,
            data.len()
        );
        match io.write(data).await {
            Ok(n) if n == data.len() => FDStatus {
                open: true,
                last: true,
                data: None,
            },
            Ok(n) => FDStatus {
                open: true,
                last: true,
                data: Some(data[n..].into()),
            },
            Err(e) => match e.kind() {
                std::io::ErrorKind::BrokenPipe => {
                    self.detach_channel_selector(id, selector).await;
                    FDStatus {
                        open: false,
                        last: false,
                        data: Some(data.into()),
                    }
                }
                std::io::ErrorKind::WouldBlock => FDStatus {
                    open: true,
                    last: false,
                    data: Some(data.into()),
                },
                _ => {
                    trace!(logger, "channel {}: {}: error writing: {}", id, selector, e);
                    FDStatus {
                        open: true,
                        last: false,
                        data: Some(data.into()),
                    }
                }
            },
        }
    }

    async fn read_command_fd<T: AsyncReadExt + Unpin>(
        &self,
        id: ChannelID,
        selector: u32,
        st: &FDStatus,
        io: &mut T,
    ) -> FDStatus {
        let logger = self.config.logger();
        if !st.open {
            trace!(logger, "channel {}: closed selector {}", id, selector);
            return st.clone();
        }
        let mut buf = vec![0; 65536];
        let data = match &st.data {
            Some(data) => data,
            None => {
                let mut interval = time::interval(Duration::from_millis(10));
                trace!(
                    logger,
                    "channel {}: {}: about to read from fd",
                    id,
                    selector
                );
                select! {
                    res = io.read(&mut buf) => {
                        trace!(logger, "channel {}: {}: got {:?} on read", id, selector, res);
                        match res {
                            Ok(0) => {
                                trace!(logger, "channel {}: {}: eof on read", id, selector);
                                self.detach_channel_selector(id, selector).await;
                                return FDStatus{open: false, last: false, data: None};
                            },
                            Ok(n) => &buf[0..n],
                            Err(_) => return st.clone(),
                        }
                    }
                    _ = interval.tick() => {
                        trace!(logger, "channel {}: {}: nothing to read", id, selector);
                        return FDStatus{open: st.open, last: false, data: st.data.clone()};
                    }
                }
            }
        };
        trace!(
            logger,
            "channel {}: {}: about to write {} bytes to channel",
            id,
            selector,
            data.len()
        );
        match self.write_channel(id, selector, data).await {
            Ok(x) if x == data.len() as u64 => {
                trace!(
                    logger,
                    "channel {}: {}: write channel: {} bytes",
                    id,
                    selector,
                    x
                );
                FDStatus {
                    open: true,
                    last: true,
                    data: None,
                }
            }
            Ok(x) => {
                trace!(
                    logger,
                    "channel {}: {}: write channel: {} bytes",
                    id,
                    selector,
                    x
                );
                FDStatus {
                    open: true,
                    last: true,
                    data: Some(data[(x as usize)..].to_vec()),
                }
            }
            Err(e) => {
                trace!(
                    logger,
                    "channel {}: {}: write channel: error {}",
                    id,
                    selector,
                    e
                );
                use std::error::Error;
                if let Some(e) = e.source() {
                    if let Some(handler::Error::ProtocolError(e)) =
                        e.downcast_ref::<handler::Error>()
                    {
                        let e: Result<std::io::Error, _> = e.clone().try_into();
                        if let Ok(e) = e {
                            match e.kind() {
                                std::io::ErrorKind::BrokenPipe => {
                                    return FDStatus {
                                        open: false,
                                        last: false,
                                        data: None,
                                    }
                                }
                                std::io::ErrorKind::WouldBlock => {
                                    return FDStatus {
                                        open: true,
                                        last: false,
                                        data: Some(data.to_vec()),
                                    }
                                }
                                _ => {
                                    return FDStatus {
                                        open: true,
                                        last: false,
                                        data: Some(data.to_vec()),
                                    }
                                }
                            }
                        }
                    }
                }
                FDStatus {
                    open: true,
                    last: false,
                    data: Some(data.to_vec()),
                }
            }
        }
    }

    async fn read_channel(&self, id: ChannelID, selector: u32) -> Result<Bytes, Error> {
        let req = ReadChannelRequest {
            id,
            selector,
            count: 65536,
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

    async fn read_channel_internal(
        handler: Arc<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>>,
        id: ChannelID,
        selector: u32,
        count: u64,
    ) -> Result<Bytes, Error> {
        let req = ReadChannelRequest {
            id,
            selector,
            count,
        };
        let resp: ReadChannelResponse = match handler
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

    async fn write_channel(&self, id: ChannelID, selector: u32, data: &[u8]) -> Result<u64, Error> {
        let req = WriteChannelRequest {
            id,
            selector,
            bytes: data.to_vec().into(),
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

    async fn write_channel_internal(
        handler: Arc<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>>,
        id: ChannelID,
        selector: u32,
        data: Bytes,
    ) -> Result<u64, Error> {
        let req = WriteChannelRequest {
            id,
            selector,
            bytes: data.to_vec().into(),
        };
        let resp: WriteChannelResponse = match handler
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

    async fn detach_channel_selector(&self, id: ChannelID, selector: u32) {
        Self::detach_channel_selector_internal(
            self.config.logger(),
            self.handler.clone(),
            id,
            selector,
        )
        .await
    }

    async fn detach_channel_selector_internal(
        logger: Arc<config::Logger>,
        handler: Arc<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>>,
        id: ChannelID,
        selector: u32,
    ) {
        let req = DetachChannelSelectorRequest { id, selector };
        let res = handler
            .send_message::<_, Empty, Empty>(MessageKind::DetachChannelSelector, &req, Some(false))
            .await;
        trace!(
            logger,
            "channel {}: {}: detach selector: {:?}",
            id,
            selector,
            res
        );
    }

    async fn create_command_channel(&self, args: &[Bytes]) -> Result<ChannelID, Error> {
        let config = self.config.clone();
        let req = CreateChannelRequest {
            kind: (b"command" as &'static [u8]).into(),
            kind_args: None,
            args: Some(args.into()),
            env: Some(config.env_vars().clone()),
            meta: None,
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

type SelectorResult = Result<BTreeMap<u32, u64>, Error>;

enum ReadFutureState {
    Idle,
    IO(Pin<Box<dyn Future<Output = Result<Bytes, Error>> + Send + Sync + 'static>>),
    Poll(Pin<Box<dyn Future<Output = SelectorResult> + Send + Sync + 'static>>),
    Value(Result<u64, io::Error>),
}

enum WriteFutureState {
    Idle,
    IO(Pin<Box<dyn Future<Output = Result<u64, Error>> + Send + Sync + 'static>>),
    Poll(Pin<Box<dyn Future<Output = SelectorResult> + Send + Sync + 'static>>),
    Value(Result<u64, io::Error>),
}

enum DetachFutureState {
    Idle,
    IO(Pin<Box<dyn Future<Output = ()> + Send + Sync + 'static>>),
    Value,
}

struct ChannelReader {
    config: Arc<Config>,
    handler: Arc<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>>,
    id: ChannelID,
    selector: u32,
    state: ReadFutureState,
    extra: Vec<u8>,
}

impl ChannelReader {
    fn new(
        config: Arc<Config>,
        handler: Arc<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>>,
        id: ChannelID,
        selector: u32,
    ) -> Self {
        Self {
            config,
            handler,
            id,
            selector,
            state: ReadFutureState::Idle,
            extra: Vec::new(),
        }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let config = self.config.clone();
        let selector = self.selector;
        let handler = self.handler.clone();
        let id = self.id;
        let nself = self.get_mut();
        loop {
            let state = match nself.state {
                ReadFutureState::IO(ref mut rf) => {
                    trace!(config.logger(), "client: {}: {}: i/o state", id, selector);
                    let res = ready!(rf.as_mut().poll(cx));
                    trace!(
                        config.logger(),
                        "client: {}: {}: i/o state is ready",
                        id,
                        selector
                    );
                    match res {
                        Ok(val) => {
                            trace!(
                                config.logger(),
                                "client: {}: {}: read is ready and returns {} ({} filled, {} remaining)",
                                id,
                                selector,
                                val.len(),
                                buf.filled().len(),
                                buf.remaining(),
                            );
                            let count = std::cmp::min(val.len(), buf.remaining());
                            buf.initialize_unfilled_to(count)
                                .copy_from_slice(&val[0..count]);
                            buf.set_filled(count);
                            if count < val.len() {
                                nself.extra.extend(&val[count..]);
                            }
                            trace!(
                                config.logger(),
                                "client: {}: {}: read is done ({} filled)",
                                id,
                                selector,
                                buf.filled().len()
                            );
                            ReadFutureState::Value(Ok(val.len() as u64))
                        }
                        Err(e) => {
                            trace!(
                                config.logger(),
                                "client: {}: {}: read is ready and returns {:?}",
                                id,
                                selector,
                                e
                            );
                            let e: Result<io::Error, _> = e.try_into();
                            match e {
                                Ok(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    let mut selectors = BTreeMap::new();
                                    selectors.insert(
                                        selector,
                                        PollChannelFlags::Input | PollChannelFlags::Hangup,
                                    );
                                    let fut = Box::pin(Connection::poll_channel(
                                        config.clone(),
                                        handler.clone(),
                                        id,
                                        selectors,
                                    ));
                                    ReadFutureState::Poll(fut)
                                }
                                Ok(e) => ReadFutureState::Value(Err(e)),
                                Err(_) => ReadFutureState::Value(Err(
                                    io::Error::from_raw_os_error(libc::EBADMSG),
                                )),
                            }
                        }
                    }
                }
                ReadFutureState::Poll(ref mut pf) => {
                    trace!(config.logger(), "client: {}: {}: poll state", id, selector);
                    let _ = ready!(pf.as_mut().poll(cx));
                    trace!(
                        config.logger(),
                        "client: {}: {}: poll state is ready",
                        id,
                        selector
                    );
                    ReadFutureState::Idle
                }
                ReadFutureState::Idle => {
                    trace!(config.logger(), "client: {}: {}: idle state", id, selector);
                    if !nself.extra.is_empty() {
                        let count = std::cmp::min(nself.extra.len(), buf.remaining());
                        buf.initialize_unfilled_to(count)
                            .copy_from_slice(&nself.extra[0..count]);
                        buf.set_filled(count);
                        nself.extra.drain(0..count);
                        trace!(
                            config.logger(),
                            "client: {}: {}: copied {} extra elements ({} remaining)",
                            id,
                            selector,
                            count,
                            nself.extra.len()
                        );
                        ReadFutureState::Value(Ok(count as u64))
                    } else {
                        let fut = Box::pin(Connection::read_channel_internal(
                            handler.clone(),
                            id,
                            selector,
                            buf.remaining() as u64,
                        ));
                        trace!(
                            config.logger(),
                            "client: {}: {}: idle state created pin",
                            id,
                            selector
                        );
                        ReadFutureState::IO(fut)
                    }
                }
                _ => unreachable!(),
            };
            trace!(
                config.logger(),
                "client: {}: {}: transitioning state",
                id,
                selector
            );
            match state {
                ReadFutureState::Value(val) => {
                    nself.state = ReadFutureState::Idle;
                    return match val {
                        Ok(_) => Poll::Ready(Ok(())),
                        Err(e) => Poll::Ready(Err(e)),
                    };
                }
                _ => nself.state = state,
            }
        }
    }
}

struct ChannelWriter {
    config: Arc<Config>,
    handler: Arc<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>>,
    id: ChannelID,
    selector: u32,
    write_state: WriteFutureState,
    shutdown_state: DetachFutureState,
}

impl ChannelWriter {
    fn new(
        config: Arc<Config>,
        handler: Arc<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>>,
        id: ChannelID,
        selector: u32,
    ) -> Self {
        Self {
            config,
            handler,
            id,
            selector,
            write_state: WriteFutureState::Idle,
            shutdown_state: DetachFutureState::Idle,
        }
    }
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let config = self.config.clone();
        let selector = self.selector;
        let handler = self.handler.clone();
        let id = self.id;
        let nself = self.get_mut();
        let buf = Bytes::copy_from_slice(buf);
        loop {
            let state = match nself.write_state {
                WriteFutureState::IO(ref mut rf) => {
                    let res = ready!(rf.as_mut().poll(cx));
                    match res {
                        Ok(val) => WriteFutureState::Value(Ok(val)),
                        Err(e) => {
                            let e: Result<io::Error, _> = e.try_into();
                            match e {
                                Ok(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    let mut selectors = BTreeMap::new();
                                    selectors.insert(
                                        selector,
                                        PollChannelFlags::Input | PollChannelFlags::Hangup,
                                    );
                                    let fut = Box::pin(Connection::poll_channel(
                                        config.clone(),
                                        handler.clone(),
                                        id,
                                        selectors,
                                    ));
                                    WriteFutureState::Poll(fut)
                                }
                                Ok(e) => WriteFutureState::Value(Err(e)),
                                Err(_) => WriteFutureState::Value(Err(
                                    io::Error::from_raw_os_error(libc::EBADMSG),
                                )),
                            }
                        }
                    }
                }
                WriteFutureState::Poll(ref mut pf) => {
                    let _ = ready!(pf.as_mut().poll(cx));
                    WriteFutureState::Idle
                }
                WriteFutureState::Idle => {
                    let fut = Box::pin(Connection::write_channel_internal(
                        handler.clone(),
                        id,
                        selector,
                        buf.clone(),
                    ));
                    WriteFutureState::IO(fut)
                }
                _ => unreachable!(),
            };
            match state {
                WriteFutureState::Value(val) => {
                    nself.write_state = WriteFutureState::Idle;
                    return match val {
                        Ok(val) => Poll::Ready(Ok(val as usize)),
                        Err(e) => Poll::Ready(Err(e)),
                    };
                }
                _ => nself.write_state = state,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let config = self.config.clone();
        let selector = self.selector;
        let handler = self.handler.clone();
        let id = self.id;
        let nself = self.get_mut();
        let state = match nself.shutdown_state {
            DetachFutureState::IO(ref mut fut) => {
                ready!(fut.as_mut().poll(cx));
                DetachFutureState::Value
            }
            DetachFutureState::Idle => {
                let fut = Box::pin(Connection::detach_channel_selector_internal(
                    config.logger(),
                    handler,
                    id,
                    selector,
                ));
                DetachFutureState::IO(fut)
            }
            _ => unreachable!(),
        };
        match state {
            DetachFutureState::Value => {
                nself.shutdown_state = DetachFutureState::Idle;
                Poll::Ready(Ok(()))
            }
            _ => {
                nself.shutdown_state = state;
                Poll::Pending
            }
        }
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
    ) -> Result<Connection, Error> {
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
    ) -> Result<Connection, Error> {
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
