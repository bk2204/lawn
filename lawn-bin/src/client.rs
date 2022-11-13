#![allow(dead_code)]

use crate::config::Config;
use crate::encoding::{escape, path};
use crate::error::{Error, ErrorKind};
use bytes::Bytes;
use lawn_protocol::config::Logger;
use lawn_protocol::handler::ProtocolHandler;
use lawn_protocol::protocol;
use lawn_protocol::protocol::{
    AuthenticateRequest, AuthenticateResponse, CapabilityResponse, ChannelID,
    ChannelMetadataNotification, ChannelMetadataNotificationKind, ChannelMetadataStatusKind,
    ClipboardChannelOperation, ClipboardChannelTarget, CreateChannelRequest, CreateChannelResponse,
    DeleteChannelRequest, DetachChannelSelectorRequest, Empty, MessageKind, PollChannelFlags,
    PollChannelRequest, PollChannelResponse, ReadChannelRequest, ReadChannelResponse,
    VersionRequest, WriteChannelRequest, WriteChannelResponse,
};
use num_traits::FromPrimitive;
use serde_cbor::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::select;
use tokio::time;

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
    handler: Arc<Option<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>>>,
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
        let handler = Arc::new(Some(ProtocolHandler::new(cfg, sread, swrite, synchronous)));
        Self {
            config,
            path: path.map(|p| p.into()),
            handler,
        }
    }

    pub async fn ping(&self) -> Result<(), Error> {
        let handler = match self.handler.as_ref() {
            Some(handler) => handler,
            None => return Err(Error::new(ErrorKind::NotConnected)),
        };
        handler
            .send_message_simple::<Empty>(MessageKind::Ping, Some(true))
            .await?;
        Ok(())
    }

    pub async fn capability(&self) -> Result<CapabilityResponse, Error> {
        let handler = match self.handler.as_ref() {
            Some(handler) => handler,
            None => return Err(Error::new(ErrorKind::NotConnected)),
        };
        match handler
            .send_message_simple(MessageKind::Capability, Some(true))
            .await?
        {
            Some(resp) => Ok(resp),
            None => Err(Error::new(ErrorKind::MissingResponse)),
        }
    }

    pub async fn negotiate_default_version(&self) -> Result<CapabilityResponse, Error> {
        let handler = match self.handler.as_ref() {
            Some(handler) => handler,
            None => return Err(Error::new(ErrorKind::NotConnected)),
        };
        let resp: CapabilityResponse = match handler
            .send_message_simple(MessageKind::Capability, Some(true))
            .await?
        {
            Some(resp) => resp,
            None => return Err(Error::new(ErrorKind::MissingResponse)),
        };
        let ours = protocol::Capability::implemented();
        let theirs: BTreeSet<protocol::Capability> = resp
            .capabilities
            .iter()
            .cloned()
            .filter_map(|c| c.try_into().ok())
            .collect();
        let req = VersionRequest {
            version: 0,
            enable: ours.union(&theirs).map(|x| (*x).into()).collect(),
            id: None,
        };
        handler
            .send_message::<_, Empty>(MessageKind::Version, &req, Some(true))
            .await?;
        Ok(resp)
    }

    pub async fn auth_external(&self) -> Result<AuthenticateResponse, Error> {
        let handler = match self.handler.as_ref() {
            Some(handler) => handler,
            None => return Err(Error::new(ErrorKind::NotConnected)),
        };
        let req = AuthenticateRequest {
            last_id: None,
            method: "EXTERNAL".into(),
            message: None,
        };
        match handler
            .send_message(MessageKind::Authenticate, &req, Some(true))
            .await?
        {
            Some(resp) => Ok(resp),
            None => Err(Error::new(ErrorKind::MissingResponse)),
        }
    }

    pub async fn run_clipboard<I: AsyncReadExt + Unpin, O: AsyncWriteExt + Unpin>(
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

    pub async fn run_9p<I: AsyncReadExt + Unpin, O: AsyncWriteExt + Unpin>(
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

    pub async fn run_command<
        I: AsyncReadExt + Unpin,
        O: AsyncWriteExt + Unpin,
        E: AsyncWriteExt + Unpin,
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
        I: AsyncReadExt + Unpin,
        O: AsyncWriteExt + Unpin,
        E: AsyncWriteExt + Unpin,
    >(
        &self,
        stdin: I,
        stdout: O,
        stderr: E,
        id: ChannelID,
        fd_status: &mut [FDStatus],
    ) -> Result<i32, Error> {
        let mut stdin = stdin;
        let mut stdout = stdout;
        let mut stderr = stderr;
        let (polltx, mut pollrx) = tokio::sync::mpsc::unbounded_channel();
        let (cfg, chandler) = (self.config.clone(), self.handler.clone());
        let mut selectors = BTreeMap::new();
        selectors.insert(1, PollChannelFlags::Input | PollChannelFlags::Hangup);
        if fd_status.len() > 2 {
            selectors.insert(2, PollChannelFlags::Input | PollChannelFlags::Hangup);
        }
        tokio::spawn(async move {
            loop {
                let results =
                    Self::poll_channel(cfg.clone(), chandler.clone(), id, &selectors).await;
                let _ = polltx.send(results);
            }
        });
        let rhandler = self.handler.clone();
        let (finaltx, mut finalrx) = tokio::sync::mpsc::channel(1);
        let logger = self.config.logger();
        tokio::spawn(async move {
            let handler = match rhandler.as_ref() {
                Some(handler) => handler,
                None => return,
            };
            loop {
                let msg = handler.recv().await;
                trace!(logger, "received packet");
                if let Ok(Some(msg)) = msg {
                    trace!(logger, "received async response");
                    if let Some(code) = Self::handle_async_run_message(handler, &msg) {
                        trace!(logger, "sending final message");
                        finaltx.send(Ok(code)).await.unwrap();
                    }
                }
            }
        });
        let logger = self.config.logger();
        let mut buf = [0u8; 65536];
        loop {
            select! {
                res = finalrx.recv() => {
                    trace!(logger, "processing final message");
                    fd_status[0] = self.read_command_fd(id, 0, &fd_status[0], &mut stdin).await;
                    fd_status[1] = self.write_command_fd(id, 1, &fd_status[1], &mut stdout).await;
                    if fd_status.len() > 2 {
                        fd_status[2] = self.write_command_fd(id, 2, &fd_status[2], &mut stderr).await;
                    }

                    while fd_status[0].needs_final_read() {
                        fd_status[0] = self.read_command_fd(id, 0, &fd_status[0], &mut stdin).await;
                    }
                    while fd_status[1].needs_final_write() {
                        fd_status[1] = self.write_command_fd(id, 1, &fd_status[1], &mut stdout).await;
                    }
                    while fd_status.len() > 2 && fd_status[2].needs_final_write() {
                        fd_status[2] = self.write_command_fd(id, 2, &fd_status[2], &mut stderr).await;
                    }
                    let _ = self.delete_channel(id).await;
                    trace!(logger, "returning value");
                    return res.unwrap();
                }
                res = stdin.read(&mut buf), if fd_status[0].open => {
                    match res {
                        Ok(x) if x != 0 => {
                            match &mut fd_status[0].data {
                                Some(data) => data.extend(&buf[0..x]),
                                None => fd_status[0].data = Some(buf[0..x].into()),
                            }
                            fd_status[0] = self.read_command_fd(id, 0, &fd_status[0], &mut stdin).await;
                        },
                        Ok(0) => fd_status[0] = self.read_command_fd(id, 0, &fd_status[0], &mut stdin).await,
                        _ => (),
                    }
                }
                results = pollrx.recv() => {
                    trace!(logger, "channel {}: poll: results {:?}", id, results);
                    let results = results.unwrap();
                    if let Ok(results) = results {
                        if let Some(flags) = results.get(&0) {
                            let mask = (PollChannelFlags::Output | PollChannelFlags::Hangup | PollChannelFlags::Invalid).bits();
                            if (flags & mask) != 0 {
                                trace!(logger, "channel {}: selector 0: reading", id);
                                fd_status[0] = self.read_command_fd(id, 0, &fd_status[0], &mut stdin).await;
                            }
                        }
                        if let Some(flags) = results.get(&1) {
                            let mask = (PollChannelFlags::Input | PollChannelFlags::Hangup | PollChannelFlags::Invalid).bits();
                            if (flags & mask) != 0 {
                                trace!(logger, "channel {}: selector 1: writing", id);
                                fd_status[1] = self.write_command_fd(id, 1, &fd_status[1], &mut stdout).await;
                            }
                        }
                        if let Some(flags) = results.get(&2) {
                            let mask = (PollChannelFlags::Input | PollChannelFlags::Hangup | PollChannelFlags::Invalid).bits();
                            if (flags & mask) != 0 && fd_status.len() > 2 {
                                trace!(logger, "channel {}: selector 2: writing", id);
                                fd_status[2] = self.write_command_fd(id, 2, &fd_status[2], &mut stderr).await;
                            }
                        }
                    }
                }
            }
        }
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
        handler: Arc<Option<ProtocolHandler<OwnedReadHalf, OwnedWriteHalf>>>,
        id: ChannelID,
        selectors: &BTreeMap<u32, protocol::PollChannelFlags>,
    ) -> Result<BTreeMap<u32, u64>, Error> {
        let handler = match handler.as_ref() {
            Some(handler) => handler,
            None => return Err(Error::new(ErrorKind::NotConnected)),
        };
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
        let resp: PollChannelResponse = match handler
            .send_message(MessageKind::PollChannel, &req, Some(false))
            .await?
        {
            Some(resp) => resp,
            None => return Err(Error::new(ErrorKind::MissingResponse)),
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
                _ => st.clone(),
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
        let mut buf = [0; 65536];
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
                                        data: Some(data.to_vec()),
                                    }
                                }
                                _ => return st.clone(),
                            }
                        }
                    }
                }
                FDStatus {
                    open: true,
                    last: false,
                    data: None,
                }
            }
        }
    }

    async fn read_channel(&self, id: ChannelID, selector: u32) -> Result<Bytes, Error> {
        let handler = match self.handler.as_ref() {
            Some(handler) => handler,
            None => return Err(Error::new(ErrorKind::NotConnected)),
        };
        let req = ReadChannelRequest {
            id,
            selector,
            count: 65536,
        };
        let resp: ReadChannelResponse = match handler
            .send_message(MessageKind::ReadChannel, &req, Some(false))
            .await?
        {
            Some(resp) => resp,
            None => return Err(Error::new(ErrorKind::MissingResponse)),
        };
        Ok(resp.bytes)
    }

    async fn write_channel(&self, id: ChannelID, selector: u32, data: &[u8]) -> Result<u64, Error> {
        let handler = match self.handler.as_ref() {
            Some(handler) => handler,
            None => return Err(Error::new(ErrorKind::NotConnected)),
        };
        let req = WriteChannelRequest {
            id,
            selector,
            bytes: data.to_vec().into(),
        };
        let resp: WriteChannelResponse = match handler
            .send_message(MessageKind::WriteChannel, &req, Some(false))
            .await?
        {
            Some(resp) => resp,
            None => return Err(Error::new(ErrorKind::MissingResponse)),
        };
        Ok(resp.count)
    }

    async fn detach_channel_selector(&self, id: ChannelID, selector: u32) {
        let handler = match self.handler.as_ref() {
            Some(handler) => handler,
            None => return,
        };
        let req = DetachChannelSelectorRequest { id, selector };
        let _ = handler
            .send_message::<_, Empty>(MessageKind::DetachChannelSelector, &req, Some(false))
            .await;
    }

    async fn create_command_channel(&self, args: &[Bytes]) -> Result<ChannelID, Error> {
        let handler = match self.handler.as_ref() {
            Some(handler) => handler,
            None => return Err(Error::new(ErrorKind::NotConnected)),
        };
        let config = self.config.clone();
        let req = CreateChannelRequest {
            kind: (b"command" as &'static [u8]).into(),
            kind_args: None,
            args: Some(args.into()),
            env: Some(config.env_vars().clone()),
            meta: None,
            selectors: vec![0, 1, 2],
        };
        let resp: CreateChannelResponse = match handler
            .send_message(MessageKind::CreateChannel, &req, Some(true))
            .await?
        {
            Some(resp) => resp,
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
        let handler = match self.handler.as_ref() {
            Some(handler) => handler,
            None => return Err(Error::new(ErrorKind::NotConnected)),
        };
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
        let resp: CreateChannelResponse = match handler
            .send_message(MessageKind::CreateChannel, &req, Some(true))
            .await?
        {
            Some(resp) => resp,
            None => return Err(Error::new(ErrorKind::MissingResponse)),
        };
        Ok(resp.id)
    }

    async fn create_9p_channel(&self, target: Bytes) -> Result<ChannelID, Error> {
        let handler = match self.handler.as_ref() {
            Some(handler) => handler,
            None => return Err(Error::new(ErrorKind::NotConnected)),
        };
        let req = CreateChannelRequest {
            kind: (b"9p" as &'static [u8]).into(),
            kind_args: None,
            args: Some(vec![target]),
            env: Some(self.config.env_vars().clone()),
            meta: None,
            selectors: vec![0, 1],
        };
        let resp: CreateChannelResponse = match handler
            .send_message(MessageKind::CreateChannel, &req, Some(true))
            .await?
        {
            Some(resp) => resp,
            None => return Err(Error::new(ErrorKind::MissingResponse)),
        };
        Ok(resp.id)
    }

    async fn delete_channel(&self, id: ChannelID) -> Result<(), Error> {
        let handler = match self.handler.as_ref() {
            Some(handler) => handler,
            None => return Err(Error::new(ErrorKind::NotConnected)),
        };
        let req = DeleteChannelRequest {
            id,
            termination: None,
        };
        handler
            .send_message::<_, Empty>(MessageKind::DeleteChannel, &req, Some(false))
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
