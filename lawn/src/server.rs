use crate::channel::{
    Channel, ChannelManager, Server9PChannel, ServerClipboardChannel, ServerCommandChannel,
    ServerSFTPChannel,
};
use crate::config;
use crate::config::{Config, Logger};
use crate::encoding::{escape, path};
use crate::error::{Error, ErrorKind};
use crate::socket::{LawnSocketData, LawnSocketKind};
use crate::store::credential::CredentialStore;
use crate::store::StoreManager;
use crate::store::{StoreElement, StoreElementEntry};
use crate::unix;
use bytes::Bytes;
use daemonize::Daemonize;
use lawn_constants::logger::AsLogStr;
use lawn_protocol::config::Logger as LoggerTrait;
use lawn_protocol::handler;
use lawn_protocol::handler::{ExtensionError, ExtensionMap, ProtocolHandler};
use lawn_protocol::protocol;
use lawn_protocol::protocol::{Message, MessageKind, ResponseCode};
use num_traits::cast::FromPrimitive;
use serde_cbor::Value;
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::marker::Unpin;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net;
use tokio::select;
use tokio::signal;
use tokio::sync;
use tokio::task;
use tokio::time;

macro_rules! valid_message {
    ($handler:expr, $type:ty, $msg:expr) => {{
        let r: Result<Option<$type>, _> = $handler.serializer().deserialize_message_typed($msg);
        match r {
            Ok(Some(m)) => m,
            Ok(None) | Err(_) => {
                return Err(ResponseCode::Invalid.into());
            }
        }
    }};
}

macro_rules! assert_authenticated {
    ($handler:expr, $msg:expr) => {{
        if !$handler.authenticated().await {
            return Err(ResponseCode::NeedsAuthentication.into());
        }
    }};
}

macro_rules! assert_capability {
    ($handler:expr, $capa:expr) => {{
        if !$handler.has_capability(&$capa).await {
            return Err(ResponseCode::NotEnabled.into());
        }
    }};
}

enum ResponseType {
    Success,
    Partial,
    Close,
}

type ContinuationMapByID = HashMap<u32, Box<dyn Any + Send>>;

struct Continuations {
    data: Mutex<HashMap<MessageKind, ContinuationMapByID>>,
}

impl Continuations {
    fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }

    fn insert<T: Any + Send + 'static>(&self, kind: MessageKind, id: u32, data: T) {
        let mut g = self.data.lock().unwrap();
        let e = g.entry(kind).or_default();
        e.insert(id, Box::<T>::new(data));
    }

    fn remove<T: Any + Send + 'static>(&self, kind: MessageKind, id: u32) -> Option<Box<T>> {
        let mut g = self.data.lock().unwrap();
        let m = g.get_mut(&kind)?;
        let e = m.remove(&id)?;
        e.downcast().ok()
    }
}

struct ExtensionContinuation {
    off: usize,
}

struct ListStoreContinuation {
    next: Arc<dyn StoreElementEntry + Send + Sync>,
    iter: Box<dyn Iterator<Item = Arc<dyn StoreElementEntry + Send + Sync>> + Send + Sync>,
}

struct SearchStoreContinuation {
    next: Arc<dyn StoreElement + Send + Sync>,
    iter: Box<dyn Iterator<Item = Arc<dyn StoreElement + Send + Sync>> + Send + Sync>,
}

struct AuthenticateStoreElementContinuation {
    method: Bytes,
    id: protocol::StoreID,
    selector: protocol::StoreSelectorID,
}

pub struct Server {
    config: Arc<Config>,
    destroyer: Mutex<Option<sync::oneshot::Sender<()>>>,
}

impl Server {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            destroyer: Mutex::new(None),
        }
    }

    pub fn run(&self) -> Result<(), Error> {
        let logger = self.config.logger();
        logger.trace("server: checking if we are going to detach");
        let (fdrd, fdwr) = self.pipe()?;
        let mut fdwr = Some(fdwr);
        if self.config.detach() {
            logger.trace("server: yes, we will detach");
            self.daemonize(Some(fdrd))?;
        } else {
            fdwr = None;
            std::mem::drop(fdrd);
            logger.trace("server: no, we will not detach");
        }
        let mut socket_path: PathBuf = self.config.runtime_dir();
        socket_path.push("server-0.sock");
        logger.trace(&format!(
            "server: socket is {}",
            escape(path(socket_path.as_ref()))
        ));
        logger.trace("server: starting runtime");
        self.runtime(&socket_path, fdwr)
    }

    #[allow(dead_code)]
    pub async fn run_async(self: Arc<Self>) -> Result<File, Error> {
        let logger = self.config.logger();
        let mut socket_path: PathBuf = self.config.runtime_dir();
        socket_path.push("server-0.sock");
        logger.trace(&format!(
            "server: socket is {}",
            escape(path(socket_path.as_ref()))
        ));
        let (tx, rx) = sync::oneshot::channel();
        {
            let mut g = self.destroyer.lock().unwrap();
            *g = Some(tx);
        }
        let (fdrd, fdwr) = self.pipe()?;
        tokio::spawn(async move { self.runtime_async(&socket_path, Some(fdwr), rx).await });
        Ok(fdrd)
    }

    #[allow(dead_code)]
    pub async fn shutdown(&self) {
        let rx = {
            let mut g = self.destroyer.lock().unwrap();
            g.take()
        };
        if let Some(rx) = rx {
            let _ = rx.send(());
        }
    }

    pub fn run_forked(&self) -> Result<(), Error> {
        let logger = self.config.logger();
        logger.trace("server: checking if we are going to detach");
        let (fdrd, fdwr) = self.pipe()?;
        match unix::call_with_result(|| unsafe { libc::fork() })
            .map_err(|e| Error::new_with_cause(ErrorKind::ServerCreationFailure, e))?
        {
            // child
            0 => {
                std::mem::drop(fdrd);
                if self.config.detach() {
                    logger.trace("server: yes, we will detach");
                    self.daemonize(None)?;
                } else {
                    logger.trace("server: no, we will not detach");
                }
                let mut socket_path: PathBuf = self.config.runtime_dir();
                socket_path.push("server-0.sock");
                logger.trace(&format!(
                    "server: socket is {}",
                    escape(path(socket_path.as_ref()))
                ));
                logger.trace("server: starting runtime");
                let _ = self.runtime(&socket_path, Some(fdwr));
                std::process::exit(0);
            }
            _ => {
                std::mem::drop(fdwr);
                let mut fdrd = fdrd;
                let mut buf = [0u8; 1];
                let _ = fdrd.read(&mut buf);
                Ok(())
            }
        }
    }

    fn pipe(&self) -> Result<(File, File), Error> {
        let mut pipefd = [-1i32; 2];
        unix::call_with_result(|| unsafe { libc::pipe(pipefd.as_mut_ptr()) })
            .map_err(|e| Error::new_with_cause(ErrorKind::ServerCreationFailure, e))?;
        Ok((unsafe { File::from_raw_fd(pipefd[0]) }, unsafe {
            File::from_raw_fd(pipefd[1])
        }))
    }

    #[tokio::main]
    async fn runtime(&self, socket_path: &Path, fdwr: Option<File>) -> Result<(), Error> {
        let (tx, rx) = sync::oneshot::channel();
        {
            let mut g = self.destroyer.lock().unwrap();
            *g = Some(tx);
        }
        self.runtime_async(socket_path, fdwr, rx).await
    }

    async fn runtime_async(
        &self,
        socket_path: &Path,
        fdwr: Option<File>,
        rx: sync::oneshot::Receiver<()>,
    ) -> Result<(), Error> {
        let mut rx = rx;
        let logger = self.config.logger();
        logger.trace("server: runtime started, installing SIGTERM handler");
        let mut sig =
            signal::unix::signal(signal::unix::SignalKind::terminate()).map_err(|_| {
                Error::new_with_message(
                    ErrorKind::ServerCreationFailure,
                    "cannot install signal handler",
                )
            })?;
        logger.trace("server: binding socket");
        let socket = net::UnixListener::bind(socket_path).map_err(|_| {
            Error::new_with_message(ErrorKind::ServerCreationFailure, "cannot bind to socket")
        })?;
        self.config.set_socket_data(LawnSocketData::new(
            LawnSocketKind::Lawn,
            Bytes::copy_from_slice(socket_path.as_os_str().as_bytes()),
        ));
        let mut interval = time::interval(Duration::from_secs(1));
        let mut counter = 0u64;
        type JobInfo = (sync::mpsc::Sender<()>, task::JoinHandle<u64>);
        let storage: sync::Mutex<HashMap<u64, JobInfo>> = sync::Mutex::new(HashMap::new());
        if let Some(fdwr) = fdwr {
            logger.trace("server: writing pipe");
            let mut fdwr = fdwr;
            let _ = fdwr.write_all(&[0x00]);
        }
        let shared_state = SharedServerState::new(self.config.clone());
        logger.trace("server: starting main loop");
        loop {
            select! {
                _ = sig.recv() => {
                    logger.trace("server: received SIGTERM");
                    {
                        let mut g = storage.lock().await;
                        for (tx, _) in g.values_mut() {
                            let _ = tx.send(()).await;
                        }
                        for (_, (_, handle)) in g.drain() {
                            let _ = handle.await;
                        }
                    }
                    return Ok(());
                }
                res = &mut rx => {
                    {
                        let mut g = storage.lock().await;
                        for (tx, _) in g.values_mut() {
                            let _ = tx.send(()).await;
                        }
                        for (_, (_, handle)) in g.drain() {
                            let _ = handle.await;
                        }
                    }
                    if res.is_ok() {
                        return Ok(());
                    }
                }
                conn = socket.accept() => {
                    // TODO: gracefully handle the disappearance of our socket
                    if let Ok((conn, _)) = conn {
                        let id = counter;
                        counter += 1;
                        trace!(logger, "server: accepted connection, spawning handler {}", id);
                        let (tx, rx) = sync::mpsc::channel(1);
                        let config = self.config.clone();
                        let shst = shared_state.clone();
                        let handle = task::spawn(async move {
                            let logger = config.logger();
                            Self::run_job(shst, id, rx, conn).await;
                            trace!(logger, "server: exiting handler {}", id);
                            id
                        });
                        {
                            let mut g = storage.lock().await;
                            g.insert(id, (tx, handle));
                        }
                    }
                }
                _ = interval.tick() => {
                    let mut to_delete = BTreeSet::new();
                    {
                        let mut g = storage.lock().await;
                        for (id, (_, handle)) in g.iter_mut() {
                            let mut ready = false;
                            select!{
                                val = tokio::time::timeout(Duration::from_millis(5), handle) => {
                                    if val.is_ok() {
                                        ready = true;
                                    }
                                }
                            }
                            if ready {
                                trace!(logger, "server: pruning idle handler {}", id);
                                to_delete.insert(*id);
                            }
                        }
                    }
                    {
                        let mut g = storage.lock().await;
                        for id in to_delete {
                            g.remove(&id);
                        }
                    }
                }
            }
        }
    }

    async fn run_job(
        shared_state: Arc<SharedServerState>,
        id: u64,
        rx: sync::mpsc::Receiver<()>,
        conn: net::UnixStream,
    ) {
        let mut rx = rx;
        let cfg = Arc::new(lawn_protocol::config::Config::new(
            true,
            shared_state.config().logger(),
        ));
        let (chandeathtx, mut chandeathrx) = sync::mpsc::channel(10);
        let (connread, connwrite) = conn.into_split();
        let state = Arc::new(ServerState {
            handler: Arc::new(ProtocolHandler::new(
                cfg.clone(),
                connread,
                connwrite,
                false,
            )),
            channels: Arc::new(ChannelManager::new(Some(chandeathtx))),
            stores: Arc::new(StoreManager::new()),
            extensions: Arc::new(RwLock::new(ExtensionMap::new())),
            continuations: Continuations::new(),
            shared_state,
        });
        let handler = state.handler();
        let channels = state.channels();
        let logger = state.logger();
        trace!(logger, "server: {}: starting main loop", id);
        let mut interval = time::interval(Duration::from_millis(100));
        let (msg_tx, mut msg_rx) = sync::mpsc::channel(1);
        let phandler = handler.clone();
        tokio::spawn(async move {
            loop {
                let msg = phandler.recv().await;
                if msg_tx.send(msg).await.is_err() {
                    return;
                }
            }
        });
        loop {
            select! {
                _ = rx.recv() => {
                    trace!(logger, "server: {}: received quit signal from server", id);
                    handler.close(true).await;
                    return;
                },
                _ = interval.tick() => {
                    trace!(logger, "server: {}: periodic loop: pinging channels", id);
                    // Idle loop.
                    channels.ping_channels().await;
                }
                res = msg_rx.recv() => {
                    trace!(logger, "server: {}: message received", id);
                    let state = state.clone();
                    let res = match res {
                        Some(r) => r,
                        None => return,
                    };
                    match res {
                        Ok(None) => (),
                        Ok(Some(msg)) => {
                            tokio::spawn(async move {
                                let msgid = msg.id;
                                let logger = state.logger();
                                let handle = tokio::spawn(async move {
                                    let handler = state.handler();
                                    let logger = state.logger();
                                    trace!(logger, "server: {}: processing message {}", id, msg.id);
                                    match Self::process_message(state.clone(), id, &msg).await {
                                        Ok((ResponseType::Close, body)) => {
                                            trace!(logger, "server: {}: message {}: code {:08x} (closing)", id, msg.id, 0);
                                            let _ = handler.send_success(msg.id, body).await;
                                            handler.close(false).await;
                                        }
                                        Err(handler::Error::ProtocolError(protocol::Error{code, body: Some(body)})) => {
                                            trace!(logger, "server: {}: message {}: code {:08x} (body)", id, msg.id, code as u32);
                                            match handler.send_error_typed(msg.id, code, &body).await {
                                                Ok(_) => (),
                                                Err(_) => handler.close(true).await,
                                            }
                                        },
                                        Err(handler::Error::ProtocolError(protocol::Error{code, body: None})) => {
                                            trace!(logger, "server: {}: message {}: code {:08x}", id, msg.id, code as u32);
                                            match handler.send_error_simple(msg.id, code).await {
                                                Ok(_) => (),
                                                Err(_) => handler.close(true).await,
                                            }
                                        },
                                        Err(e) => {
                                            trace!(logger, "server: {}: message {}: error: {} (closing)", id, msg.id, e);
                                            handler.close(true).await;
                                        },
                                        Ok((ResponseType::Success, body)) => {
                                            trace!(logger, "server: {}: message {}: code {:08x}", id, msg.id, 0);
                                            match handler.send_success(msg.id, body).await {
                                                Ok(_) => (),
                                                Err(_) => handler.close(true).await,
                                            }
                                            trace!(logger, "server: {}: message {}: code {:08x} sent", id, msg.id, 0);
                                        },
                                        Ok((ResponseType::Partial, body)) => {
                                            trace!(logger, "server: {}: message {}: code {:08x}", id, msg.id, 0);
                                            match handler.send_continuation(msg.id, body).await {
                                                Ok(_) => (),
                                                Err(_) => handler.close(true).await,
                                            }
                                            trace!(logger, "server: {}: message {}: code {:08x} sent", id, msg.id, 0);
                                        },
                                    }
                                });
                                match handle.await {
                                    Ok(_) => (),
                                    Err(e) if e.is_cancelled() => {
                                        trace!(logger, "server: {}: message {}: cancelled", id, msgid);
                                    },
                                    Err(e) if e.is_panic() => {
                                        let e = e.into_panic();
                                        if let Some(e) = e.downcast_ref::<&str>() {
                                            trace!(logger, "server: {}: message {}: panic: {}", id, msgid, e);
                                        } else if let Some(e) = e.downcast_ref::<String>() {
                                            trace!(logger, "server: {}: message {}: panic: {}", id, msgid, e);
                                        } else {
                                            trace!(logger, "server: {}: message {}: unknown panic", id, msgid);
                                        }
                                    },
                                    Err(_) => {
                                        trace!(logger, "server: {}: message {}: unknown error", id, msgid);
                                    }
                                }
                            });
                        }
                        Err(handler::Error::IOError(_)) | Err(handler::Error::Unserializable) | Err(handler::Error::Undeserializable) => {
                            handler.close(true).await;
                            return;
                        },
                        // These cannot occur, and we will ignore them.
                        Err(handler::Error::NoResponseReceived) | Err(handler::Error::ProtocolError(_)) | Err(handler::Error::Aborted) | Err(handler::Error::TooManyMessages) => (),
                    }
                },
                chanid = chandeathrx.recv() => {
                    if let Some(chanid) = chanid {
                        trace!(logger, "server: {}: received channel death for channel {}", id, chanid);
                        let state = state.clone();
                        task::spawn(async move {
                            Self::notify_channel_death(state, chanid).await;
                        });
                    }
                },
                else => {
                }
            }
        }
    }

    async fn notify_channel_death<T: AsyncRead + Unpin, U: AsyncWrite + Unpin>(
        state: Arc<ServerState<T, U>>,
        id: protocol::ChannelID,
    ) {
        let logger = state.logger();
        let ch = match state.channels().get(id) {
            Some(ch) => ch,
            None => return,
        };
        if !ch.is_alive() {
            return;
        }
        ch.set_dead();
        match ch.ping() {
            // This shouldn't happen, but if it does, do nothing
            Ok(()) => {
                logger.error(&format!(
                    "server: channel {} was supposed to be dead, but it is not",
                    id.0
                ));
            }
            Err(e) => {
                if let Some(protocol::ErrorBody::Exit(st)) = e.body {
                    let st = std::process::ExitStatus::from_raw(st);
                    let (code, kind) = if let Some(sig) = st.signal() {
                        // TODO: map signals.
                        // TODO: handle core_dumped on 1.58
                        (
                            Some(sig as u32),
                            Some(protocol::ChannelMetadataStatusKind::Signalled as u32),
                        )
                    } else if let Some(exit) = st.code() {
                        (
                            Some(exit as u32),
                            Some(protocol::ChannelMetadataStatusKind::Exited as u32),
                        )
                    } else {
                        (
                            None,
                            Some(protocol::ChannelMetadataStatusKind::Unknown as u32),
                        )
                    };
                    let msg = protocol::ChannelMetadataNotification {
                        id,
                        kind: protocol::ChannelMetadataNotificationKind::WaitStatus as u32,
                        status: code,
                        status_kind: kind,
                        meta: None,
                    };
                    let _: Result<
                        Option<protocol::ResponseValue<protocol::Empty, protocol::Empty>>,
                        _,
                    > = state
                        .handler()
                        .send_message(
                            protocol::MessageKind::ChannelMetadataNotification,
                            &msg,
                            Some(false),
                        )
                        .await;
                }
            }
        }
    }

    /// Processes a message of the appropriate type.
    ///
    /// Returns a tuple indicating the kind of response and an optional success message, or on
    /// failure an error.
    #[allow(clippy::mutable_key_type)]
    async fn process_message<T: AsyncRead + Unpin, U: AsyncWrite + Unpin>(
        state: Arc<ServerState<T, U>>,
        id: u64,
        message: &Message,
    ) -> Result<(ResponseType, Option<Bytes>), handler::Error> {
        let handler = state.handler();
        let serializer = handler.serializer();
        let channels = state.channels();
        let stores = state.stores();
        let logger = state.logger();
        match MessageKind::from_u32(message.kind) {
            Some(MessageKind::Capability) => {
                trace!(logger, "server: {}: capability message", id);
                let c = protocol::CapabilityResponse {
                    version: vec![0x00000000],
                    capabilities: state
                        .config()
                        .capabilities()
                        .iter()
                        .map(|c| (*c).clone().into())
                        .collect(),
                    user_agent: Some(config::VERSION.into()),
                };
                Ok((ResponseType::Success, serializer.serialize_body(&c)))
            }
            Some(MessageKind::Version) => {
                trace!(logger, "server: {}: version message", id);
                handler.flush_requests().await;
                let m = valid_message!(handler, protocol::VersionRequest, message);
                let supported = state.config().capabilities();
                let requested: BTreeSet<protocol::Capability> =
                    m.enable.iter().cloned().map(|c| c.into()).collect();
                if m.version != 0x00000000 {
                    return Err(ResponseCode::ParametersNotSupported.into());
                }
                logger.trace(&format!(
                    "server: {}: version: negotiated v{}; supported {:?}; requested {:?}; user_agent {:?}",
                    id, m.version, supported, requested, m.user_agent,
                ));
                // There are unsupported types.
                if requested.difference(&supported).next().is_some() {
                    Err(ResponseCode::ParametersNotSupported.into())
                } else {
                    handler.set_capabilities(&requested).await;
                    Ok((ResponseType::Success, None))
                }
            }
            Some(MessageKind::CloseAlert) => {
                trace!(logger, "server: {}: close alert", id);
                Ok((ResponseType::Close, None))
            }
            Some(MessageKind::Ping) => {
                trace!(logger, "server: {}: ping", id);
                Ok((ResponseType::Success, None))
            }
            Some(MessageKind::Authenticate) => {
                trace!(logger, "server: {}: authenticate", id);
                handler.flush_requests().await;
                let m = valid_message!(handler, protocol::AuthenticateRequest, message);
                if m.last_id.is_some() || m.message.is_some() || m.method != b"EXTERNAL" as &[u8] {
                    return Err(ResponseCode::ParametersNotSupported.into());
                }
                handler.set_authenticated(true).await;
                let r = protocol::AuthenticateResponse {
                    method: m.method,
                    message: None,
                };
                Ok((ResponseType::Success, serializer.serialize_body(&r)))
            }
            Some(MessageKind::Continue) => {
                trace!(logger, "server: {}: continue", id);
                let m = valid_message!(handler, protocol::PartialContinueRequest, message);
                let kind = MessageKind::from_u32(m.kind).ok_or_else::<handler::Error, _>(|| {
                    ResponseCode::ParametersNotSupported.into()
                })?;
                let id = m.id;
                if kind != MessageKind::Authenticate {
                    assert_authenticated!(handler, message);
                }
                match kind {
                    MessageKind::ListExtensionRanges => {
                        let cont = state
                            .continuations
                            .remove::<ExtensionContinuation>(kind, id)
                            .ok_or_else::<handler::Error, _>(|| {
                                ResponseCode::ContinuationNotFound.into()
                            })?;
                        let ext = state.extensions.read().unwrap();
                        let mut it = ext.iter();
                        let chunk = it
                            .by_ref()
                            .skip(cont.off)
                            .take(100)
                            .map(|(_, ext)| protocol::ExtensionRange {
                                extension: ext.extension.clone(),
                                range: (ext.base, ext.base + ext.count),
                            })
                            .collect();
                        let kind = if it.next().is_some() {
                            state.continuations.insert(
                                MessageKind::ListExtensionRanges,
                                message.id,
                                ExtensionContinuation {
                                    off: cont.off + 100,
                                },
                            );
                            ResponseType::Partial
                        } else {
                            ResponseType::Success
                        };
                        let resp = protocol::ListExtensionRangesResponse { ranges: chunk };
                        Ok((kind, serializer.serialize_body(&resp)))
                    }
                    MessageKind::ListStoreElements => {
                        let cont = state
                            .continuations
                            .remove::<ListStoreContinuation>(kind, id)
                            .ok_or_else::<handler::Error, _>(|| {
                                ResponseCode::ContinuationNotFound.into()
                            })?;
                        let mut it = cont.iter;
                        let chunk: Vec<protocol::StoreElement> = [cont.next]
                            .iter()
                            .cloned()
                            .chain(it.by_ref().take(99))
                            .map(|elem| protocol::StoreElement {
                                path: elem.path(),
                                id: None,
                                kind: String::from_utf8_lossy(&elem.kind()).to_string(),
                                needs_authentication: elem.needs_authentication(),
                                authentication_methods: None,
                                meta: None,
                            })
                            .collect();
                        let kind = match it.next() {
                            Some(elem) => {
                                state.continuations.insert(
                                    MessageKind::ListStoreElements,
                                    id,
                                    ListStoreContinuation {
                                        next: elem,
                                        iter: it,
                                    },
                                );
                                ResponseType::Partial
                            }
                            None => ResponseType::Success,
                        };
                        let resp = protocol::ListStoreElementsResponse { elements: chunk };
                        Ok((kind, serializer.serialize_body(&resp)))
                    }
                    MessageKind::SearchStoreElements => {
                        let cont = state
                            .continuations
                            .remove::<SearchStoreContinuation>(kind, id)
                            .ok_or_else::<handler::Error, _>(|| {
                                ResponseCode::ContinuationNotFound.into()
                            })?;
                        let mut it = cont.iter;
                        let chunk: Vec<protocol::StoreElementWithBody<_>> = [cont.next]
                            .iter()
                            .cloned()
                            .chain(it.by_ref().take(99))
                            .filter_map(|elem| {
                                let body = match elem.body() {
                                    Ok(Some(body)) => body,
                                    Ok(None) => return None,
                                    Err(e) => return Some(Err(e)),
                                };
                                // TODO: convert when other store types are implemeneted
                                let cse =
                                    body.downcast_ref::<protocol::CredentialStoreElement>()?;
                                Some(Ok(protocol::StoreElementWithBody {
                                    path: elem.path(),
                                    id: Some(elem.id()),
                                    kind: String::from_utf8_lossy(&elem.kind()).to_string(),
                                    needs_authentication: elem.needs_authentication(),
                                    authentication_methods: None,
                                    meta: None,
                                    body: (*cse).clone(),
                                }))
                            })
                            .collect::<Result<_, _>>()?;
                        let kind = match it.next() {
                            Some(elem) => {
                                state.continuations.insert(
                                    MessageKind::SearchStoreElements,
                                    id,
                                    SearchStoreContinuation {
                                        next: elem,
                                        iter: it,
                                    },
                                );
                                ResponseType::Partial
                            }
                            None => ResponseType::Success,
                        };
                        let resp = protocol::SearchStoreElementsResponse { elements: chunk };
                        Ok((kind, serializer.serialize_body(&resp)))
                    }
                    MessageKind::AuthenticateStoreElement => {
                        let m = valid_message!(
                            handler,
                            protocol::ContinueRequest<protocol::AuthenticateStoreElementRequest>,
                            message
                        );
                        let cont = state
                            .continuations
                            .remove::<AuthenticateStoreElementContinuation>(kind, id)
                            .ok_or_else::<handler::Error, _>(|| {
                                ResponseCode::ContinuationNotFound.into()
                            })?;
                        let msg = m
                            .message
                            .as_ref()
                            .ok_or(ResponseCode::ParametersNotSupported)?;
                        let st = match stores.get(cont.id) {
                            Some(st) => st,
                            None => return Err(ResponseCode::NotFound.into()),
                        };
                        if cont.method != msg.method
                            || cont.id != msg.id
                            || cont.selector != msg.selector
                        {
                            return Err(ResponseCode::Invalid.into());
                        }
                        match st.get(cont.selector) {
                            Some(se) => {
                                match se.authenticate(cont.method.clone(), msg.message.clone()) {
                                    Ok((resp, more)) => {
                                        let resp = protocol::AuthenticateStoreElementResponse {
                                            method: cont.method.clone(),
                                            message: resp,
                                        };
                                        let code = if more {
                                            state.continuations.insert(
                                                MessageKind::AuthenticateStoreElement,
                                                id,
                                                AuthenticateStoreElementContinuation {
                                                    method: cont.method,
                                                    id: cont.id,
                                                    selector: cont.selector,
                                                },
                                            );
                                            ResponseType::Partial
                                        } else {
                                            ResponseType::Success
                                        };
                                        Ok((code, serializer.serialize_body(&resp)))
                                    }
                                    Err(e) => {
                                        trace!(
                                            logger,
                                            "server: {}: authenticate store element: error: {}",
                                            id,
                                            e
                                        );
                                        Err(e.into())
                                    }
                                }
                            }
                            None => {
                                trace!(
                                    logger,
                                    "server: {}: authenticate store element: not present",
                                    id
                                );
                                Err(ResponseCode::NotFound.into())
                            }
                        }
                    }
                    _ => Err(ResponseCode::ContinuationNotFound.into()),
                }
            }
            Some(MessageKind::Abort) => {
                let m = valid_message!(handler, protocol::PartialContinueRequest, message);
                let kind = MessageKind::from_u32(m.kind).ok_or_else::<handler::Error, _>(|| {
                    ResponseCode::ParametersNotSupported.into()
                })?;
                let id = m.id;
                if kind != MessageKind::Authenticate {
                    assert_authenticated!(handler, message);
                }
                // The type here doesn't matter; it will be removed regardless, which is what we
                // want.
                state
                    .continuations
                    .remove::<ExtensionContinuation>(kind, id);
                Ok((ResponseType::Success, None))
            }
            Some(MessageKind::CreateChannel) => {
                trace!(logger, "server: {}: create channel", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::CreateChannelRequest, message);
                logger.trace(&format!(
                    "server: {}: create channel: {}: {}",
                    id,
                    escape(&m.kind),
                    handler
                        .has_capability(&protocol::Capability::ChannelCommand)
                        .await
                ));
                let kind: &[u8] = &m.kind;
                let res = match kind {
                    b"command"
                        if handler
                            .has_capability(&protocol::Capability::ChannelCommand)
                            .await =>
                    {
                        Self::create_command_channel(id, state.clone(), &m).await
                    }
                    b"clipboard"
                        if handler
                            .has_capability(&protocol::Capability::ChannelClipboard)
                            .await =>
                    {
                        Self::create_clipboard_channel(id, state.clone(), &m).await
                    }
                    b"9p"
                        if handler
                            .has_capability(&protocol::Capability::Channel9P)
                            .await =>
                    {
                        Self::create_9p_channel(id, state.clone(), &m).await
                    }
                    b"sftp"
                        if handler
                            .has_capability(&protocol::Capability::ChannelSFTP)
                            .await =>
                    {
                        Self::create_sftp_channel(id, state.clone(), &m).await
                    }
                    _ => return Err(ResponseCode::ParametersNotSupported.into()),
                };
                match res {
                    Ok(id) => {
                        let r = protocol::CreateChannelResponse { id };
                        Ok((ResponseType::Success, serializer.serialize_body(&r)))
                    }
                    Err(_) => {
                        trace!(logger, "server: {}: create channel: failed", id);
                        Err(ResponseCode::InvalidParameters.into())
                    }
                }
            }
            Some(MessageKind::ReadChannel) => {
                trace!(logger, "server: {}: read channel", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::ReadChannelRequest, message);
                let ch = match channels.get(m.id) {
                    Some(ch) => ch,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                let selector = m.selector;
                let count = m.count;
                let data = tokio::task::spawn_blocking(move || ch.read(selector, count))
                    .await
                    .unwrap()?;
                let resp = protocol::ReadChannelResponse { bytes: data };
                Ok((ResponseType::Success, serializer.serialize_body(&resp)))
            }
            Some(MessageKind::WriteChannel) => {
                trace!(logger, "server: {}: write channel", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::WriteChannelRequest, message);
                let ch = match channels.get(m.id) {
                    Some(ch) => ch,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                let selector = m.selector;
                let bytes = m.bytes;
                let n = tokio::task::spawn_blocking(move || ch.write(selector, bytes))
                    .await
                    .unwrap()?;
                let resp = protocol::WriteChannelResponse { count: n };
                Ok((ResponseType::Success, serializer.serialize_body(&resp)))
            }
            Some(MessageKind::DeleteChannel) => {
                trace!(logger, "server: {}: delete channel", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::DeleteChannelRequest, message);
                match channels.remove(m.id) {
                    Some(ch) => std::mem::drop(ch),
                    None => return Err(ResponseCode::NotFound.into()),
                };
                Ok((ResponseType::Success, None))
            }
            Some(MessageKind::DetachChannelSelector) => {
                trace!(logger, "server: {}: detach channel selector", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::DetachChannelSelectorRequest, message);
                let ch = match channels.get(m.id) {
                    Some(ch) => ch,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                match ch.detach_selector(m.selector) {
                    Ok(()) => Ok((ResponseType::Success, None)),
                    Err(e) => Err(e.into()),
                }
            }
            Some(MessageKind::PollChannel) => {
                trace!(logger, "server: {}: poll channel", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::PollChannelRequest, message);
                let ch = match channels.get(m.id) {
                    Some(ch) => ch,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                if !ch.is_alive() {
                    return Err(ResponseCode::ChannelDead.into());
                }
                let duration = Duration::from_millis(m.milliseconds.unwrap_or(0) as u64);
                let (tx, rx) = sync::oneshot::channel();
                let selectors = m.selectors.clone();
                let flags = m.wanted.clone();
                tokio::task::spawn_blocking(move || ch.poll(selectors, flags, duration, tx));
                let rxresp = match rx.await {
                    Ok(resp) => resp?,
                    Err(_) => return Err(ResponseCode::InternalError.into()),
                };
                let resp = protocol::PollChannelResponse {
                    id: m.id,
                    selectors: m
                        .selectors
                        .iter()
                        .cloned()
                        .zip(rxresp.iter().cloned().map(|x| x.bits()))
                        .collect(),
                };
                Ok((ResponseType::Success, serializer.serialize_body(&resp)))
            }
            Some(MessageKind::PingChannel) => {
                trace!(logger, "server: {}: ping channel", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::PingChannelRequest, message);
                let ch = match channels.get(m.id) {
                    Some(ch) => ch,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                ch.ping()?;
                Ok((ResponseType::Success, None))
            }
            Some(MessageKind::CreateExtensionRange) => {
                trace!(logger, "server: {}: create extension range", id);
                assert_capability!(handler, protocol::Capability::ExtensionAllocate);
                let m = valid_message!(handler, protocol::CreateExtensionRangeRequest, message);
                let mut ext = state.extensions.write().unwrap();
                match ext.insert(None, m.extension, m.count) {
                    Ok(base) => {
                        let resp = protocol::CreateExtensionRangeResponse {
                            range: (base, base + m.count),
                        };
                        Ok((ResponseType::Success, serializer.serialize_body(&resp)))
                    }
                    Err(ExtensionError::RangeTooLarge) => Err(ResponseCode::OutOfRange.into()),
                    Err(ExtensionError::RangeInUse) => Err(ResponseCode::Conflict.into()),
                    Err(ExtensionError::NoSpace) => Err(ResponseCode::NoSpace.into()),
                    Err(_) => Err(ResponseCode::InternalError.into()),
                }
            }
            Some(MessageKind::DeleteExtensionRange) => {
                trace!(logger, "server: {}: delete extension range", id);
                assert_capability!(handler, protocol::Capability::ExtensionAllocate);
                let m = valid_message!(handler, protocol::DeleteExtensionRangeRequest, message);
                let mut ext = state.extensions.write().unwrap();
                match ext.remove(m.range.0, m.extension) {
                    Ok(()) => Ok((ResponseType::Success, None)),
                    Err(_) => Err(ResponseCode::NotFound.into()),
                }
            }
            Some(MessageKind::ListExtensionRanges) => {
                trace!(logger, "server: {}: list extension ranges", id);
                assert_authenticated!(handler, message);
                assert_capability!(handler, protocol::Capability::ExtensionAllocate);
                let ext = state.extensions.read().unwrap();
                let mut it = ext.iter();
                let chunk = it
                    .by_ref()
                    .take(100)
                    .map(|(_, ext)| protocol::ExtensionRange {
                        extension: ext.extension.clone(),
                        range: (ext.base, ext.base + ext.count),
                    })
                    .collect();
                let kind = if it.next().is_some() {
                    state.continuations.insert(
                        MessageKind::ListExtensionRanges,
                        message.id,
                        ExtensionContinuation { off: 100 },
                    );
                    ResponseType::Partial
                } else {
                    ResponseType::Success
                };
                let resp = protocol::ListExtensionRangesResponse { ranges: chunk };
                Ok((kind, serializer.serialize_body(&resp)))
            }
            Some(MessageKind::OpenStore) => {
                trace!(logger, "server: {}: open store", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::OpenStoreRequest, message);
                logger.trace(&format!("server: {}: open store: {}", id, escape(&m.kind),));
                let kind: &[u8] = &m.kind;
                let res: Result<_, handler::Error> = match kind {
                    b"credential"
                        if handler
                            .has_capability(&protocol::Capability::StoreCredential)
                            .await =>
                    {
                        let id = stores.next_id();
                        stores.insert(
                            id,
                            Arc::new(CredentialStore::new(
                                id,
                                state.config(),
                                state.shared_state.clone(),
                            )),
                        );
                        Ok(id)
                    }
                    _ => return Err(ResponseCode::ParametersNotSupported.into()),
                };
                match res {
                    Ok(id) => {
                        let r = protocol::OpenStoreResponse { id };
                        Ok((ResponseType::Success, serializer.serialize_body(&r)))
                    }
                    Err(_) => {
                        trace!(logger, "server: {}: open store: failed", id);
                        Err(ResponseCode::InvalidParameters.into())
                    }
                }
            }
            Some(MessageKind::ListStoreElements) => {
                trace!(logger, "server: {}: list store elements", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::ListStoreElementsRequest, message);
                trace!(logger, "server: {}: list store elements: {}", id, m.id.0);
                let st = match stores.get(m.id) {
                    Some(st) => st,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                let se = match m.selector {
                    protocol::StoreSelector::Path(path) => match st.acquire(path)? {
                        Some(se) => se,
                        None => return Err(ResponseCode::NotFound.into()),
                    },
                    protocol::StoreSelector::ID(selector) => match st.get(selector) {
                        Some(se) => se,
                        None => return Err(ResponseCode::NotFound.into()),
                    },
                };
                let mut it = match (se.is_directory(), se.contents()) {
                    (false, _) => {
                        trace!(
                            logger,
                            "server: {}: list store elements: not a directory",
                            id
                        );
                        return Err(ResponseCode::NotSupported.into());
                    }
                    (true, Err(e)) => {
                        trace!(
                            logger,
                            "server: {}: list store elements: directory with error: {}",
                            id,
                            e
                        );
                        return Err(e.into());
                    }
                    (true, Ok(None)) => {
                        trace!(
                            logger,
                            "server: {}: list store elements: directory with no data",
                            id
                        );
                        return Err(ResponseCode::NotSupported.into());
                    }
                    (true, Ok(Some(it))) => {
                        trace!(logger, "server: {}: list store elements: found items", id);
                        it
                    }
                };
                let chunk: Vec<_> = it
                    .by_ref()
                    .take(100)
                    .map(|elem| protocol::StoreElement {
                        path: elem.path(),
                        id: None,
                        kind: String::from_utf8_lossy(&elem.kind()).to_string(),
                        needs_authentication: elem.needs_authentication(),
                        authentication_methods: elem
                            .authentication_metadata()
                            .map(|meta| meta.methods().to_owned()),
                        meta: None,
                    })
                    .collect();
                trace!(
                    logger,
                    "server: {}: list store elements: chunk size: {}",
                    id,
                    chunk.len()
                );
                let kind = match it.next() {
                    Some(elem) => {
                        state.continuations.insert(
                            MessageKind::ListStoreElements,
                            message.id,
                            ListStoreContinuation {
                                next: elem,
                                iter: it,
                            },
                        );
                        ResponseType::Partial
                    }
                    None => ResponseType::Success,
                };
                let resp = protocol::ListStoreElementsResponse { elements: chunk };
                Ok((kind, serializer.serialize_body(&resp)))
            }
            Some(MessageKind::AcquireStoreElement) => {
                trace!(logger, "server: {}: acquire store element", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::AcquireStoreElementRequest, message);
                let st = match stores.get(m.id) {
                    Some(st) => st,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                let selector = match st.acquire(m.selector) {
                    Ok(Some(se)) => se.id(),
                    Ok(None) => {
                        trace!(logger, "server: {}: acquire store element: not found", id);
                        return Err(ResponseCode::NotFound.into());
                    }
                    Err(e) => {
                        trace!(
                            logger,
                            "server: {}: acquire store element: failed: {}",
                            id,
                            e
                        );
                        return Err(e.into());
                    }
                };
                let resp = protocol::AcquireStoreElementResponse { selector };
                Ok((ResponseType::Success, serializer.serialize_body(&resp)))
            }
            Some(MessageKind::CloseStoreElement) => {
                trace!(logger, "server: {}: close store element", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::CloseStoreElementRequest, message);
                let st = match stores.get(m.id) {
                    Some(st) => st,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                match st.close(m.selector) {
                    Ok(()) => Ok((ResponseType::Success, None)),
                    Err(e) => {
                        trace!(logger, "server: {}: open store element: error: {}", id, e);
                        Err(e.into())
                    }
                }
            }
            Some(MessageKind::AuthenticateStoreElement) => {
                trace!(logger, "server: {}: authenticate store element", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::AuthenticateStoreElementRequest, message);
                let st = match stores.get(m.id) {
                    Some(st) => st,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                let capabilities = state.config().capabilities();
                let desired: protocol::Capability =
                    (Bytes::from(b"auth" as &[u8]), Some(m.method.clone())).into();
                if !capabilities.contains(&desired) {
                    return Err(ResponseCode::ParametersNotSupported.into());
                }
                match st.get(m.selector) {
                    Some(se) => match se.authenticate(m.method.clone(), m.message) {
                        Ok((resp, more)) => {
                            let resp = protocol::AuthenticateStoreElementResponse {
                                method: m.method.clone(),
                                message: resp,
                            };
                            let code = if more {
                                state.continuations.insert(
                                    MessageKind::AuthenticateStoreElement,
                                    message.id,
                                    AuthenticateStoreElementContinuation {
                                        method: m.method,
                                        id: m.id,
                                        selector: m.selector,
                                    },
                                );
                                ResponseType::Partial
                            } else {
                                ResponseType::Success
                            };
                            Ok((code, serializer.serialize_body(&resp)))
                        }
                        Err(e) => {
                            trace!(
                                logger,
                                "server: {}: authenticate store element: error: {}",
                                id,
                                e
                            );
                            Err(e.into())
                        }
                    },
                    None => {
                        trace!(
                            logger,
                            "server: {}: authenticate store element: not present",
                            id
                        );
                        Err(ResponseCode::NotFound.into())
                    }
                }
            }
            Some(MessageKind::CreateStoreElement) => {
                trace!(logger, "server: {}: create store element", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::StoreElementBareRequest, message);
                let st = match stores.get(m.id) {
                    Some(st) => st,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                let path = match m.selector {
                    protocol::StoreSelector::Path(path) => path,
                    protocol::StoreSelector::ID(_) => {
                        return Err(ResponseCode::ParametersNotSupported.into())
                    }
                };
                let cred;
                let value: Option<Box<(dyn Any + Send + Sync + 'static)>> = match &*m.kind {
                    "directory" => None,
                    "credential" => {
                        cred = valid_message!(
                            handler,
                            protocol::CreateStoreElementRequest<protocol::CredentialStoreElement>,
                            message
                        );
                        Some(Box::new(cred.body))
                    }
                    _ => {
                        trace!(
                            logger,
                            "server: {}: create store element: unsupported type: {}",
                            id,
                            m.kind
                        );
                        return Err(ResponseCode::ParametersNotSupported.into());
                    }
                };
                trace!(
                    logger,
                    "server: {}: create store element: creating element of type {} at {}",
                    id,
                    m.kind,
                    path.as_ref().as_log_str(),
                );
                let cpath = path.clone();
                let cst = st.clone();
                let ckind = m.kind.clone();
                let meta = m.meta;
                match tokio::task::spawn_blocking(move || {
                    cst.create(cpath, &ckind, meta.as_ref(), value.as_deref())
                })
                .await
                {
                    Ok(Ok(se)) => {
                        let elem = protocol::StoreElement {
                            path: se.path(),
                            id: Some(se.id()),
                            kind: String::from_utf8_lossy(se.kind()).to_string(),
                            needs_authentication: se.needs_authentication(),
                            authentication_methods: se
                                .authentication_metadata()
                                .map(|m| m.methods().to_owned()),
                            meta: se.meta().as_deref().map(ToOwned::to_owned),
                        };
                        Ok((ResponseType::Success, serializer.serialize_body(&elem)))
                    }
                    Ok(Err(e)) => {
                        trace!(logger, "server: {}: create store element: error: {}", id, e);
                        Err(e.into())
                    }
                    Err(e) => {
                        trace!(
                            logger,
                            "server: {}: create store element: spawn error: {}",
                            id,
                            e
                        );
                        Err(ResponseCode::InternalError.into())
                    }
                }
            }
            Some(MessageKind::UpdateStoreElement) => {
                trace!(logger, "server: {}: update store element", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::StoreElementBareRequest, message);
                let st = match stores.get(m.id) {
                    Some(st) => st,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                let se = match m.selector {
                    protocol::StoreSelector::Path(path) => match st.acquire(path)? {
                        Some(se) => se,
                        None => return Err(ResponseCode::NotFound.into()),
                    },
                    protocol::StoreSelector::ID(selector) => match st.get(selector) {
                        Some(se) => se,
                        None => return Err(ResponseCode::NotFound.into()),
                    },
                };
                if m.kind.as_bytes() != se.kind()
                    || m.needs_authentication.is_some()
                    || m.authentication_methods.is_some()
                {
                    trace!(
                        logger,
                        "server: {}: update store element: unsupported update data: {}",
                        id,
                        m.kind
                    );
                    return Err(ResponseCode::ParametersNotSupported.into());
                }
                let cred;
                let value: Option<&(dyn Any + Send + Sync)> = match &*m.kind {
                    "directory" => None,
                    "credential" => {
                        cred = valid_message!(
                            handler,
                            protocol::UpdateStoreElementRequest<protocol::CredentialStoreElement>,
                            message
                        );
                        Some(&cred.body)
                    }
                    _ => {
                        trace!(
                            logger,
                            "server: {}: update store element: unsupported type: {}",
                            id,
                            m.kind
                        );
                        return Err(ResponseCode::ParametersNotSupported.into());
                    }
                };
                match se.update(m.meta.as_ref(), value) {
                    Ok(_) => Ok((ResponseType::Success, None)),
                    Err(e) => {
                        trace!(logger, "server: {}: update store element: error: {}", id, e);
                        Err(e.into())
                    }
                }
            }
            Some(MessageKind::DeleteStoreElement) => {
                trace!(logger, "server: {}: delete store element", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::DeleteStoreElementRequest, message);
                let st = match stores.get(m.id) {
                    Some(st) => st,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                let selector = match m.selector {
                    protocol::StoreSelector::Path(path) => match st.acquire(path)? {
                        Some(se) => se.id(),
                        None => return Err(ResponseCode::NotFound.into()),
                    },
                    protocol::StoreSelector::ID(selector) => selector,
                };
                match st.delete(selector) {
                    Ok(()) => Ok((ResponseType::Success, None)),
                    Err(e) => {
                        trace!(logger, "server: {}: delete store element: error: {}", id, e);
                        Err(e.into())
                    }
                }
            }
            Some(MessageKind::ReadStoreElement) => {
                trace!(logger, "server: {}: read store element", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::ReadStoreElementRequest, message);
                let st = match stores.get(m.id) {
                    Some(st) => st,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                let se = match m.selector {
                    protocol::StoreSelector::Path(path) => match st.acquire(path)? {
                        Some(se) => se,
                        None => return Err(ResponseCode::NotFound.into()),
                    },
                    protocol::StoreSelector::ID(selector) => match st.get(selector) {
                        Some(se) => se,
                        None => return Err(ResponseCode::NotFound.into()),
                    },
                };
                let elem = protocol::StoreElement {
                    path: se.path(),
                    id: Some(se.id()),
                    kind: String::from_utf8_lossy(se.kind()).to_string(),
                    needs_authentication: se.needs_authentication(),
                    authentication_methods: se
                        .authentication_metadata()
                        .map(|m| m.methods().to_owned()),
                    meta: se.meta().as_deref().map(ToOwned::to_owned),
                };
                match se.kind() {
                    b"directory" => Ok((ResponseType::Success, serializer.serialize_body(&elem))),
                    b"credential" => {
                        let body = se.body()?;
                        let cse: protocol::CredentialStoreElement = match body
                            .map(|b| b.downcast::<protocol::CredentialStoreElement>().ok())
                        {
                            Some(Some(cse)) => *cse,
                            Some(None) => {
                                trace!(
                                    logger,
                                    "server: {}: read store element: unable to cast",
                                    id,
                                );
                                return Err(ResponseCode::InternalError.into());
                            }
                            None => {
                                trace!(
                                    logger,
                                    "server: {}: read store element: no body provided",
                                    id,
                                );
                                return Err(ResponseCode::NotFound.into());
                            }
                        };
                        let resp = protocol::StoreElementWithBody::new(elem, cse);
                        Ok((ResponseType::Success, serializer.serialize_body(&resp)))
                    }
                    _ => {
                        trace!(
                            logger,
                            "server: {}: read store element: unsupported type: {}",
                            id,
                            se.kind().as_log_str()
                        );
                        Err(ResponseCode::ParametersNotSupported.into())
                    }
                }
            }
            Some(MessageKind::SearchStoreElements) => {
                trace!(logger, "server: {}: search store elements", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::SearchStoreElementsBareRequest, message);
                let st = match stores.get(m.id) {
                    Some(st) => st,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                trace!(
                    logger,
                    "server: {}: search store elements: selector {:?}",
                    id,
                    m.selector
                );
                let se = match m.selector {
                    protocol::StoreSelector::Path(path) => match st.acquire(path)? {
                        Some(se) => se,
                        None => return Err(ResponseCode::NotFound.into()),
                    },
                    protocol::StoreSelector::ID(selector) => match st.get(selector) {
                        Some(se) => se,
                        None => return Err(ResponseCode::NotFound.into()),
                    },
                };
                match m.kind.as_deref() {
                    Some("credential") => {
                        let m = valid_message!(
                            handler,
                            protocol::SearchStoreElementsRequest<
                                protocol::CredentialStoreSearchElement,
                            >,
                            message
                        );
                        let res = tokio::task::spawn_blocking(move || {
                            let body: Option<&(dyn Any + Send + Sync + 'static)> = match &m.body {
                                Some(b) => Some(b),
                                None => None,
                            };
                            se.search(m.kind.map(|k| k.into()), body, m.recurse)
                        })
                        .await;
                        let mut it = match res {
                            Ok(Ok(res)) => res,
                            Ok(Err(e)) => {
                                trace!(
                                    logger,
                                    "server: {}: search store element: search error: {}",
                                    id,
                                    e,
                                );
                                return Err(e.into());
                            }
                            Err(_) => return Err(ResponseCode::InternalError.into()),
                        };
                        let chunk = it
                            .by_ref()
                            .take(100)
                            .filter_map(|elem| {
                                let body = match elem.body() {
                                    Ok(Some(body)) => body,
                                    Ok(None) => return None,
                                    Err(e) => return Some(Err(e)),
                                };
                                let cse =
                                    body.downcast_ref::<protocol::CredentialStoreElement>()?;
                                Some(Ok(protocol::StoreElementWithBody {
                                    path: elem.path(),
                                    id: Some(elem.id()),
                                    kind: String::from_utf8_lossy(&elem.kind()).to_string(),
                                    needs_authentication: elem.needs_authentication(),
                                    authentication_methods: None,
                                    meta: None,
                                    body: cse.clone(),
                                }))
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        let kind = match it.next() {
                            Some(elem) => {
                                state.continuations.insert(
                                    MessageKind::ListStoreElements,
                                    message.id,
                                    SearchStoreContinuation {
                                        next: elem,
                                        iter: it,
                                    },
                                );
                                ResponseType::Partial
                            }
                            None => ResponseType::Success,
                        };
                        let resp = protocol::SearchStoreElementsResponse { elements: chunk };
                        Ok((kind, serializer.serialize_body(&resp)))
                    }
                    _ => {
                        trace!(
                            logger,
                            "server: {}: search store element: unsupported type: {}",
                            id,
                            se.kind().as_log_str()
                        );
                        Err(ResponseCode::ParametersNotSupported.into())
                    }
                }
            }
            Some(MessageKind::CloseStore) => {
                logger.trace(&format!("server: {}: close store", id));
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::CloseStoreRequest, message);
                match stores.remove(m.id) {
                    Some(ch) => std::mem::drop(ch),
                    None => return Err(ResponseCode::NotFound.into()),
                };
                Ok((ResponseType::Success, None))
            }
            Some(MessageKind::ReadServerContext) => {
                trace!(logger, "server: {}: read server context", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::ReadServerContextRequest, message);
                trace!(logger, "server: {}: read server context: {}", id, m.kind);
                if !handler
                    .has_capability(&protocol::Capability::ContextTemplate)
                    .await
                {
                    return Err(ResponseCode::ParametersNotSupported.into());
                }
                match &*m.kind {
                    "template" => match m.id {
                        Some(ctxid) => {
                            let tctxs = state.config().template_contexts();
                            let tctxs = tctxs.read().unwrap();
                            match tctxs.get(&ctxid) {
                                Some(ctx) => {
                                    if let (Some(kind), Some(extra)) = (&ctx.kind, &ctx.extra) {
                                        let mut meta = BTreeMap::new();
                                        meta.insert(
                                            Bytes::from("template-type"),
                                            serde_cbor::Value::Text(kind.clone()),
                                        );
                                        let mut body = protocol::TemplateServerContextBodyWithBody::<
                                            &serde_cbor::Value,
                                        >::from(
                                            ctx.as_ref()
                                        );
                                        body.body = Some(extra);
                                        let resp = protocol::ReadServerContextResponseWithBody {
                                            id: Some(ctxid.clone()),
                                            meta: Some(meta),
                                            body: Some(body),
                                        };
                                        Ok((
                                            ResponseType::Success,
                                            serializer.serialize_body(&resp),
                                        ))
                                    } else {
                                        let body =
                                            protocol::TemplateServerContextBody::from(ctx.as_ref());
                                        let resp = protocol::ReadServerContextResponseWithBody {
                                            id: Some(ctxid.clone()),
                                            meta: None,
                                            body: Some(body),
                                        };
                                        Ok((
                                            ResponseType::Success,
                                            serializer.serialize_body(&resp),
                                        ))
                                    }
                                }
                                None => {
                                    trace!(
                                        logger,
                                        "server: {}: read server context: no such context {:?}",
                                        id,
                                        ctxid
                                    );
                                    Err(ResponseCode::NotFound.into())
                                }
                            }
                        }
                        None => {
                            trace!(
                                logger,
                                "server: {}: read server context: no template ID requested",
                                id,
                            );
                            Err(ResponseCode::NotFound.into())
                        }
                    },
                    _ => Err(ResponseCode::ParametersNotSupported.into()),
                }
            }
            Some(MessageKind::WriteServerContext) => {
                trace!(logger, "server: {}: write server context", id);
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::WriteServerContextRequest, message);
                trace!(logger, "server: {}: write server context: {}", id, m.kind);
                Err(ResponseCode::ParametersNotSupported.into())
            }
            Some(_) | None => {
                logger.trace(&format!(
                    "server: {}: unknown message kind {:08x}",
                    id, message.kind
                ));
                Err(ResponseCode::NotSupported.into())
            }
        }
    }

    async fn create_command_channel<T: AsyncRead + Unpin, U: AsyncWrite + Unpin>(
        id: u64,
        state: Arc<ServerState<T, U>>,
        m: &protocol::CreateChannelRequest,
    ) -> Result<protocol::ChannelID, handler::Error> {
        let allowed: HashSet<u32> = [0, 1, 2].iter().cloned().collect();
        let requested: HashSet<u32> = m.selectors.iter().cloned().collect();
        // TODO: allow requesting a subset of file descriptors.
        if allowed != requested {
            return Err(ResponseCode::ParametersNotSupported.into());
        }
        let args: Arc<[Bytes]> = match &m.args {
            Some(args) if !args.is_empty() => args.clone().into(),
            _ => return Err(ResponseCode::InvalidParameters.into()),
        };
        let config = state.config();
        let cfgcmd = match config.config_command(&args[0]) {
            Some(cmd) => cmd,
            None => return Err(ResponseCode::NotFound.into()),
        };
        let env = m.env.as_ref().map(|e| Arc::new(e.clone()));
        let ctx = config.template_context(env, Some(args.clone()));
        let logger = state.logger();
        let channels = state.channels();
        let cmd = match config::Command::new(&cfgcmd, &ctx) {
            Ok(cmd) => cmd,
            Err(e) => {
                logger.error(&format!(
                    "server: {}: failed creating template for command {}: {}",
                    id,
                    escape(&args[0]),
                    e
                ));
                return Err(ResponseCode::InternalError.into());
            }
        };
        match cmd.check_condition().await {
            Ok(true) => {
                logger.error(&format!(
                    "server: {}: condition succeeded for command {}",
                    id,
                    escape(&args[0])
                ));
            }
            Ok(false) => {
                logger.error(&format!(
                    "server: {}: condition failed for command {}",
                    id,
                    escape(&args[0])
                ));
                return Err(ResponseCode::NotFound.into());
            }
            Err(e) => {
                logger.error(&format!(
                    "server: {}: condition had error for command {}: {}",
                    id,
                    escape(&args[0]),
                    e
                ));
                return Err(ResponseCode::InternalError.into());
            }
        }
        match cmd.run_pre_hooks().await {
            Ok(true) => {
                logger.error(&format!(
                    "server: {}: pre-hooks succeeded for command {}",
                    id,
                    escape(&args[0])
                ));
            }
            Ok(false) => {
                logger.error(&format!(
                    "server: {}: pre-hooks failed for command {}",
                    id,
                    escape(&args[0])
                ));
                return Err(ResponseCode::NotFound.into());
            }
            Err(e) => {
                logger.error(&format!(
                    "server: {}: pre-hooks had error for command {}: {}",
                    id,
                    escape(&args[0]),
                    e
                ));
                return Err(ResponseCode::InternalError.into());
            }
        }
        let proc = cmd.run_std_command();
        let cid = channels.next_id();
        let ch = Arc::new(ServerCommandChannel::new(logger, cid, proc)?);
        channels.insert(cid, ch);
        Ok(cid)
    }

    async fn create_clipboard_channel<T: AsyncRead + Unpin, U: AsyncWrite + Unpin>(
        id: u64,
        state: Arc<ServerState<T, U>>,
        m: &protocol::CreateChannelRequest,
    ) -> Result<protocol::ChannelID, handler::Error> {
        #[allow(clippy::mutable_key_type)]
        let meta = match &m.meta {
            Some(meta) => meta,
            _ => return Err(ResponseCode::InvalidParameters.into()),
        };
        let target = match meta.get::<Bytes>(&(b"target" as &'static [u8]).into()) {
            Some(Value::Text(s)) if s == "primary" => protocol::ClipboardChannelTarget::Primary,
            Some(Value::Text(s)) if s == "clipboard" => protocol::ClipboardChannelTarget::Clipboard,
            None => protocol::ClipboardChannelTarget::Clipboard,
            _ => return Err(ResponseCode::InvalidParameters.into()),
        };
        let op = match meta.get::<Bytes>(&(b"operation" as &'static [u8]).into()) {
            Some(Value::Text(s)) if s == "copy" => protocol::ClipboardChannelOperation::Copy,
            Some(Value::Text(s)) if s == "paste" => protocol::ClipboardChannelOperation::Paste,
            _ => return Err(ResponseCode::InvalidParameters.into()),
        };
        let allowed: HashSet<u32> = match op {
            protocol::ClipboardChannelOperation::Copy => [0].iter().cloned().collect(),
            protocol::ClipboardChannelOperation::Paste => [1].iter().cloned().collect(),
        };
        let requested: HashSet<u32> = m.selectors.iter().cloned().collect();
        // TODO: allow requesting a subset of file descriptors.
        if allowed != requested {
            return Err(ResponseCode::ParametersNotSupported.into());
        }
        let config = state.config();
        let logger = config.logger();
        match config.clipboard_enabled() {
            Ok(true) => (),
            Ok(false) => {
                trace!(logger, "server: {}: clipboard disabled", id);
                return Err(ResponseCode::NotFound.into());
            }
            Err(e) => {
                trace!(
                    logger,
                    "server: {}: clipboard error checking if enabled: {}",
                    id,
                    e
                );
                return Err(ResponseCode::NotFound.into());
            }
        }
        let backend = match config.clipboard_backend() {
            Ok(Some(backend)) => backend,
            Ok(None) => {
                trace!(logger, "server: {}: clipboard: no backend found", id);
                return Err(ResponseCode::NotFound.into());
            }
            Err(e) => {
                trace!(
                    logger,
                    "server: {}: clipboard error getting backend: {}",
                    id,
                    e
                );
                return Err(ResponseCode::NotFound.into());
            }
        };
        if !backend.supports_target(target) {
            trace!(logger, "server: {}: clipboard: unsupported target", id);
            return Err(ResponseCode::NotFound.into());
        }
        let args = backend.command(target, op);
        let ctx = config.template_context(None, None);
        let cmd = config::std_command_from_args(&args, &ctx);
        let logger = state.logger();
        let channels = state.channels();
        let cid = channels.next_id();
        let ch = Arc::new(ServerClipboardChannel::new(logger, cid, cmd, op)?);
        channels.insert(cid, ch);
        Ok(cid)
    }

    async fn create_fs_channel<
        T: AsyncRead + Unpin,
        U: AsyncWrite + Unpin,
        FE: Fn(Arc<Config>, &str) -> Result<bool, Error>,
        FL: Fn(Arc<Config>, &str) -> Result<Option<String>, Error>,
        FS: Fn(
            Arc<Logger>,
            protocol::ChannelID,
            Bytes,
            Bytes,
        ) -> Result<Arc<dyn Channel + Send + Sync>, protocol::Error>,
    >(
        id: u64,
        state: Arc<ServerState<T, U>>,
        m: &protocol::CreateChannelRequest,
        proto_name: &str,
        enabled: FE,
        location: FL,
        start: FS,
    ) -> Result<protocol::ChannelID, handler::Error> {
        let allowed: HashSet<u32> = [0, 1].iter().cloned().collect();
        let requested: HashSet<u32> = m.selectors.iter().cloned().collect();
        if allowed != requested {
            return Err(ResponseCode::ParametersNotSupported.into());
        }
        let args = match &m.args {
            Some(args) if !args.is_empty() => args,
            _ => return Err(ResponseCode::InvalidParameters.into()),
        };
        if args.len() != 1 {
            return Err(ResponseCode::InvalidParameters.into());
        }
        let mount = match std::str::from_utf8(&args[0]) {
            Ok(s) => s,
            Err(_) => return Err(ResponseCode::InvalidParameters.into()),
        };
        let config = state.config();
        let logger = config.logger();
        match enabled(config.clone(), mount) {
            Ok(true) => (),
            Ok(false) => {
                trace!(
                    logger,
                    "server: {}: {} disabled for mount {}",
                    id,
                    proto_name,
                    mount
                );
                return Err(ResponseCode::NotFound.into());
            }
            Err(e) => {
                trace!(
                    logger,
                    "server: {}: {} error checking if enabled for mount {}: {}",
                    id,
                    proto_name,
                    mount,
                    e
                );
                return Err(ResponseCode::NotFound.into());
            }
        }
        let location = match location(config, mount) {
            Ok(Some(loc)) => {
                trace!(
                    logger,
                    "server: {}: {} mount {} points to {}",
                    id,
                    proto_name,
                    mount,
                    loc
                );
                loc
            }
            Ok(None) => {
                trace!(
                    logger,
                    "server: {}: {} mount {} does not exist",
                    id,
                    proto_name,
                    mount
                );
                return Err(ResponseCode::NotFound.into());
            }
            Err(e) => {
                trace!(
                    logger,
                    "server: {}: {} error checking if mount {} exists: {}",
                    id,
                    proto_name,
                    mount,
                    e
                );
                return Err(ResponseCode::NotFound.into());
            }
        };
        let logger = state.logger();
        let channels = state.channels();
        let cid = channels.next_id();
        let ch = start(logger, cid, mount.to_string().into(), location.into())?;
        channels.insert(cid, ch);
        Ok(cid)
    }

    async fn create_9p_channel<T: AsyncRead + Unpin, U: AsyncWrite + Unpin>(
        id: u64,
        state: Arc<ServerState<T, U>>,
        m: &protocol::CreateChannelRequest,
    ) -> Result<protocol::ChannelID, handler::Error> {
        Self::create_fs_channel(
            id,
            state,
            m,
            "9P",
            |config, mount| config.p9p_enabled(mount),
            |config, mount| config.p9p_location(mount),
            |logger, cid, mount, location| {
                Ok(Arc::new(Server9PChannel::new(
                    logger, cid, mount, location,
                )?))
            },
        )
        .await
    }

    async fn create_sftp_channel<T: AsyncRead + Unpin, U: AsyncWrite + Unpin>(
        id: u64,
        state: Arc<ServerState<T, U>>,
        m: &protocol::CreateChannelRequest,
    ) -> Result<protocol::ChannelID, handler::Error> {
        Self::create_fs_channel(
            id,
            state,
            m,
            "SFTP",
            |config, mount| config.fs_enabled(mount),
            |config, mount| config.fs_location(mount),
            |logger, cid, mount, location| {
                Ok(Arc::new(ServerSFTPChannel::new(
                    logger, cid, mount, location,
                )?))
            },
        )
        .await
    }

    fn daemonize(&self, fdrd: Option<File>) -> Result<(), Error> {
        let out = File::create("/dev/null").map_err(|_| {
            Error::new_with_message(ErrorKind::ServerCreationFailure, "cannot open /dev/null")
        })?;
        let err = File::create("/dev/null").map_err(|_| {
            Error::new_with_message(ErrorKind::ServerCreationFailure, "cannot open /dev/null")
        })?;
        let daemonize = Daemonize::new()
            .umask(0o077)
            .stdout(out)
            .stderr(err)
            .exit_action(move || {
                if let Some(fdrd) = fdrd {
                    let mut fdrd = fdrd;
                    let mut buf = [0u8; 1];
                    let _ = fdrd.read(&mut buf);
                }
            });
        match daemonize.start() {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::new_with_message(
                ErrorKind::ServerCreationFailure,
                "cannot daemonize",
            )),
        }
    }
}

/// State shared across multiple connection instances.
///
/// This struct contains data which can be shared across multiple server connections, notably data
/// for cached credentials and the configuration.
#[allow(dead_code)]
pub struct SharedServerState {
    credentials: RwLock<BTreeMap<Bytes, Arc<dyn Any + Send + Sync>>>,
    config: Arc<Config>,
}

impl SharedServerState {
    /// Create a new shared server state.
    fn new(config: Arc<Config>) -> Arc<Self> {
        Arc::new(SharedServerState {
            credentials: Default::default(),
            config,
        })
    }

    /// Get the credentials stored in this state.
    #[allow(dead_code)]
    pub fn credentials(&self) -> &RwLock<BTreeMap<Bytes, Arc<dyn Any + Send + Sync>>> {
        &self.credentials
    }

    /// Get the configuration stored in this state.
    pub fn config(&self) -> Arc<Config> {
        self.config.clone()
    }
}

struct ServerState<T: AsyncRead + Unpin, U: AsyncWrite + Unpin> {
    handler: Arc<ProtocolHandler<T, U>>,
    channels: Arc<ChannelManager>,
    stores: Arc<StoreManager>,
    extensions: Arc<RwLock<ExtensionMap>>,
    continuations: Continuations,
    shared_state: Arc<SharedServerState>,
}

impl<T: AsyncRead + Unpin, U: AsyncWrite + Unpin> ServerState<T, U> {
    fn handler(&self) -> Arc<ProtocolHandler<T, U>> {
        self.handler.clone()
    }

    fn channels(&self) -> Arc<ChannelManager> {
        self.channels.clone()
    }

    fn stores(&self) -> Arc<StoreManager> {
        self.stores.clone()
    }

    fn config(&self) -> Arc<Config> {
        self.shared_state.config.clone()
    }

    fn logger(&self) -> Arc<Logger> {
        self.shared_state.config.logger()
    }
}
