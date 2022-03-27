use crate::channel::{ChannelManager, ServerCommandChannel};
use crate::config;
use crate::config::{Config, Logger};
use crate::encoding::{escape, path};
use crate::error::{Error, ErrorKind};
use crate::unix;
use bytes::Bytes;
use daemonize::Daemonize;
use num_traits::cast::FromPrimitive;
use lawn_protocol::config::Logger as LoggerTrait;
use lawn_protocol::handler;
use lawn_protocol::handler::ProtocolHandler;
use lawn_protocol::protocol;
use lawn_protocol::protocol::{Message, MessageKind, ResponseCode};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};
use std::marker::Unpin;
use std::os::unix::io::FromRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
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
        if !$handler.authenticated() {
            return Err(ResponseCode::NeedsAuthentication.into());
        }
    }};
}

pub struct Server {
    config: Arc<Config>,
}

impl Server {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
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
        let mut interval = time::interval(Duration::from_secs(1));
        let mut counter = 0u64;
        let storage: Mutex<HashMap<u64, (sync::mpsc::Sender<()>, task::JoinHandle<u64>)>> =
            Mutex::new(HashMap::new());
        if let Some(fdwr) = fdwr {
            logger.trace("server: writing pipe");
            let mut fdwr = fdwr;
            let _ = fdwr.write_all(&[0x00]);
        }
        logger.trace("server: starting main loop");
        loop {
            select! {
                _ = sig.recv() => {
                    logger.trace("server: received SIGTERM");
                    {
                        let mut g = storage.lock().unwrap();
                        for (tx, _) in g.values_mut() {
                            let _ = tx.send(()).await;
                        }
                        for (_, (_, handle)) in g.drain() {
                            let _ = handle.await;
                        }
                    }
                    return Ok(());
                }
                conn = socket.accept() => {
                    // TODO: gracefully handle the disappearance of our socket
                    if let Ok((conn, _)) = conn {
                        let id = counter;
                        counter += 1;
                        logger.trace(&format!("server: accepted connection, spawning handler {}", id));
                        let (tx, rx) = sync::mpsc::channel(1);
                        let config = self.config.clone();
                        let handle = task::spawn(async move {
                            let logger = config.logger();
                            Self::run_job(config, id, rx, conn).await;
                            logger.trace(&format!("server: exiting handler {}", id));
                            id
                        });
                        {
                            let mut g = storage.lock().unwrap();
                            g.insert(id, (tx, handle));
                        }
                    }
                }
                _ = interval.tick() => {
                    let mut to_delete = BTreeSet::new();
                    {
                        let mut g = storage.lock().unwrap();
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
                                logger.trace(&format!("server: pruning idle handler {}", id));
                                to_delete.insert(*id);
                            }
                        }
                    }
                    {
                        let mut g = storage.lock().unwrap();
                        for id in to_delete {
                            g.remove(&id);
                        }
                    }
                }
            }
        }
    }

    async fn run_job(
        config: Arc<Config>,
        id: u64,
        rx: sync::mpsc::Receiver<()>,
        conn: net::UnixStream,
    ) {
        let mut rx = rx;
        let cfg = Arc::new(lawn_protocol::config::Config::new(
            true,
            config.logger(),
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
            config,
        });
        let handler = state.handler();
        let channels = state.channels();
        let logger = state.logger();
        logger.trace(&format!("server: {}: starting main loop", id));
        let mut interval = time::interval(Duration::from_millis(100));
        loop {
            select! {
                _ = rx.recv() => {
                    logger.trace(&format!("server: {}: received quit signal from server", id));
                    handler.close(true).await;
                    return;
                },
                _ = interval.tick() => {
                    logger.trace(&format!("server: {}: periodic loop: pinging channels", id));
                    // Idle loop.
                    channels.ping_channels().await;
                }
                res = handler.recv() => {
                    logger.trace(&format!("server: {}: message received", id));
                    let state = state.clone();
                    match res {
                        Ok(None) => (),
                        Ok(Some(msg)) => {
                            tokio::spawn(async move {
                                let handler = state.handler();
                                let logger = state.logger();
                                logger.trace(&format!("server: {}: processing message {}", id, msg.id));
                                match Self::process_message(state.clone(), id, &msg).await {
                                    Ok((true, body)) => {
                                        logger.trace(&format!("server: {}: message {}: code {:08x} (closing)", id, msg.id, 0));
                                        let _ = handler.send_success(msg.id, body).await;
                                        handler.close(false).await;
                                    }
                                    Err(handler::Error::ProtocolError(protocol::Error{code, body: Some(body)})) => {
                                        logger.trace(&format!("server: {}: message {}: code {:08x} (body)", id, msg.id, code as u32));
                                        match handler.send_error_typed(msg.id, code, &body).await {
                                            Ok(_) => (),
                                            Err(_) => handler.close(true).await,
                                        }
                                    },
                                    Err(handler::Error::ProtocolError(protocol::Error{code, body: None})) => {
                                        logger.trace(&format!("server: {}: message {}: code {:08x}", id, msg.id, code as u32));
                                        match handler.send_error_simple(msg.id, code).await {
                                            Ok(_) => (),
                                            Err(_) => handler.close(true).await,
                                        }
                                    },
                                    Err(e) => {
                                        logger.trace(&format!("server: {}: message {}: error: {} (closing)", id, msg.id, e));
                                        handler.close(true).await;
                                    },
                                    Ok((false, body)) => {
                                        logger.trace(&format!("server: {}: message {}: code {:08x}", id, msg.id, 0));
                                        match handler.send_success(msg.id, body).await {
                                            Ok(_) => (),
                                            Err(_) => handler.close(true).await,
                                        }
                                        logger.trace(&format!("server: {}: message {}: code {:08x} sent", id, msg.id, 0));
                                    },
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
                        logger.trace(&format!("server: {}: received channel death for channel {}", id, chanid));
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
                    let _: Result<Option<protocol::Empty>, _> = state
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
    /// Returns a tuple indicating whether to close the connection successfully and an optional
    /// success message, or on failure an error.
    async fn process_message<T: AsyncRead + Unpin, U: AsyncWrite + Unpin>(
        state: Arc<ServerState<T, U>>,
        id: u64,
        message: &Message,
    ) -> Result<(bool, Option<Bytes>), handler::Error> {
        let handler = state.handler();
        let serializer = handler.serializer();
        let channels = state.channels();
        let logger = state.logger();
        match MessageKind::from_u32(message.kind) {
            Some(MessageKind::Capability) => {
                logger.trace(&format!("server: {}: capability message", id));
                let c = protocol::CapabilityResponse {
                    version: vec![0x00000000],
                    capabilities: protocol::Capability::implemented()
                        .iter()
                        .map(|c| (*c).into())
                        .collect(),
                };
                Ok((false, serializer.serialize_body(&c)))
            }
            Some(MessageKind::Version) => {
                logger.trace(&format!("server: {}: version message", id));
                handler.flush_requests().await;
                let m = valid_message!(handler, protocol::VersionRequest, message);
                let supported = protocol::Capability::implemented();
                let requested: Result<BTreeSet<protocol::Capability>, _> =
                    m.enable.iter().cloned().map(|c| c.try_into()).collect();
                if m.version != 0x00000000 {
                    return Err(ResponseCode::ParametersNotSupported.into());
                }
                logger.trace(&format!(
                    "server: {}: version: negotiated v{}; supported {:?}; requested {:?}",
                    id, m.version, supported, requested
                ));
                match requested {
                    // There are unsupported types.
                    Ok(requested) if requested.difference(&supported).next().is_some() => {
                        Err(ResponseCode::ParametersNotSupported.into())
                    }
                    Err(_) => Err(ResponseCode::ParametersNotSupported.into()),
                    Ok(requested) => {
                        handler.set_capabilities(&requested);
                        Ok((false, None))
                    }
                }
            }
            Some(MessageKind::CloseAlert) => {
                logger.trace(&format!("server: {}: close alert", id));
                Ok((true, None))
            }
            Some(MessageKind::Ping) => {
                logger.trace(&format!("server: {}: ping", id));
                Ok((false, None))
            }
            Some(MessageKind::Authenticate) => {
                logger.trace(&format!("server: {}: authenticate", id));
                handler.flush_requests().await;
                let m = valid_message!(handler, protocol::AuthenticateRequest, message);
                if m.last_id.is_some() || m.message.is_some() || m.method != b"EXTERNAL" as &[u8] {
                    return Err(ResponseCode::ParametersNotSupported.into());
                }
                handler.set_authenticated(true);
                let r = protocol::AuthenticateResponse {
                    method: m.method,
                    message: None,
                };
                Ok((false, serializer.serialize_body(&r)))
            }
            Some(MessageKind::CreateChannel) => {
                logger.trace(&format!("server: {}: create channel", id));
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::CreateChannelRequest, message);
                logger.trace(&format!(
                    "server: {}: create channel: {}: {}",
                    id,
                    escape(&m.kind),
                    handler.has_capability(&protocol::Capability::ChannelCommand)
                ));
                if m.kind != b"command" as &[u8]
                    || !handler.has_capability(&protocol::Capability::ChannelCommand)
                {
                    return Err(ResponseCode::ParametersNotSupported.into());
                }
                match Self::create_command_channel(id, state.clone(), &m).await {
                    Ok(id) => {
                        let r = protocol::CreateChannelResponse { id };
                        Ok((false, serializer.serialize_body(&r)))
                    }
                    Err(_) => {
                        logger.trace(&format!("server: {}: create channel: failed", id));
                        Err(ResponseCode::InvalidParameters.into())
                    }
                }
            }
            Some(MessageKind::ReadChannel) => {
                logger.trace(&format!("server: {}: read channel", id));
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::ReadChannelRequest, message);
                let ch = match channels.get(m.id) {
                    Some(ch) => ch,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                let data = ch.read(m.selector)?;
                let resp = protocol::ReadChannelResponse { bytes: data };
                Ok((false, serializer.serialize_body(&resp)))
            }
            Some(MessageKind::WriteChannel) => {
                logger.trace(&format!("server: {}: write channel", id));
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::WriteChannelRequest, message);
                let ch = match channels.get(m.id) {
                    Some(ch) => ch,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                let n = ch.write(m.selector, m.bytes)?;
                let resp = protocol::WriteChannelResponse { count: n };
                Ok((false, serializer.serialize_body(&resp)))
            }
            Some(MessageKind::DeleteChannel) => {
                logger.trace(&format!("server: {}: delete channel", id));
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::DeleteChannelRequest, message);
                match channels.remove(m.id) {
                    Some(ch) => std::mem::drop(ch),
                    None => return Err(ResponseCode::NotFound.into()),
                };
                Ok((false, None))
            }
            Some(MessageKind::DetachChannelSelector) => {
                logger.trace(&format!("server: {}: detach channel selector", id));
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::DetachChannelSelectorRequest, message);
                let ch = match channels.get(m.id) {
                    Some(ch) => ch,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                match ch.detach_selector(m.selector) {
                    Ok(()) => Ok((false, None)),
                    Err(e) => Err(e.into()),
                }
            }
            Some(MessageKind::PollChannel) => {
                logger.trace(&format!("server: {}: poll channel", id));
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
                tokio::task::spawn_blocking(move || ch.poll(selectors, duration, tx));
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
                Ok((false, serializer.serialize_body(&resp)))
            }
            Some(MessageKind::PingChannel) => {
                logger.trace(&format!("server: {}: ping channel", id));
                assert_authenticated!(handler, message);
                let m = valid_message!(handler, protocol::PingChannelRequest, message);
                let ch = match channels.get(m.id) {
                    Some(ch) => ch,
                    None => return Err(ResponseCode::NotFound.into()),
                };
                ch.ping()?;
                Ok((false, None))
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
        let allowed: HashSet<u32> = vec![0, 1, 2].iter().cloned().collect();
        let requested: HashSet<u32> = m.selectors.iter().cloned().collect();
        // TODO: allow requesting a subset of file descriptors.
        if allowed != requested {
            return Err(ResponseCode::ParametersNotSupported.into());
        }
        let args = match &m.args {
            Some(args) if !args.is_empty() => args,
            _ => return Err(ResponseCode::InvalidParameters.into()),
        };
        let config = state.config();
        let cfgcmd = match config.config_command(&args[0]) {
            Some(cmd) => cmd,
            None => return Err(ResponseCode::NotFound.into()),
        };
        let ctx = config.template_context(m.env.as_ref(), Some(args));
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
        let proc = cmd.run_command();
        let cid = channels.next_id();
        let ch = Arc::new(ServerCommandChannel::new(logger, cid, proc)?);
        channels.insert(cid, ch);
        Ok(cid)
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

struct ServerState<T: AsyncRead + Unpin, U: AsyncWrite + Unpin> {
    handler: Arc<ProtocolHandler<T, U>>,
    channels: Arc<ChannelManager>,
    config: Arc<Config>,
}

impl<T: AsyncRead + Unpin, U: AsyncWrite + Unpin> ServerState<T, U> {
    fn handler(&self) -> Arc<ProtocolHandler<T, U>> {
        self.handler.clone()
    }

    fn channels(&self) -> Arc<ChannelManager> {
        self.channels.clone()
    }

    fn config(&self) -> Arc<Config> {
        self.config.clone()
    }

    fn logger(&self) -> Arc<Logger> {
        self.config.logger()
    }
}
