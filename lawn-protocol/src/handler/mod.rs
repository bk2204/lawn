use crate::config::Config;
use crate::protocol;
use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;
use std::io;
use std::marker::Unpin;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::select;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::Mutex;
use tokio::time;

macro_rules! dump_packet {
    ($logger:expr, $arg:expr) => {{
        use crate::config::LogLevel;
        if $logger.level() >= LogLevel::Dump {
            $logger.trace(&format!("packet: {}", hex::encode($arg)));
        }
    }};
}

#[derive(Debug)]
pub enum Error {
    IOError(io::Error),
    Unserializable,
    Undeserializable,
    NoResponseReceived,
    Aborted,
    TooManyMessages,
    ProtocolError(protocol::Error),
}

// TODO: fix
impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::IOError(e)
    }
}

impl From<protocol::Error> for Error {
    fn from(e: protocol::Error) -> Self {
        Self::ProtocolError(e)
    }
}

impl From<protocol::ResponseCode> for Error {
    fn from(e: protocol::ResponseCode) -> Self {
        Self::ProtocolError(e.into())
    }
}

struct CapabilityData {
    version: u32,
    capabilities: BTreeSet<protocol::Capability>,
}

pub struct ProtocolHandler<T: AsyncRead, U: AsyncWrite> {
    config: Arc<Config>,
    inp: tokio::sync::Mutex<Pin<Box<T>>>,
    outp: tokio::sync::Mutex<Pin<Box<U>>>,
    requests: std::sync::Mutex<HashMap<u32, Sender<Result<protocol::Response, Error>>>>,
    id: std::sync::Mutex<u32>,
    serializer: protocol::ProtocolSerializer,
    closing: std::sync::RwLock<bool>,
    capability: std::sync::RwLock<CapabilityData>,
    authenticated: std::sync::RwLock<bool>,
    synchronous: bool,
}

impl<T: AsyncRead + Unpin, U: AsyncWrite + Unpin> ProtocolHandler<T, U> {
    pub fn new(config: Arc<Config>, inp: T, outp: U, synchronous: bool) -> Self {
        let id = config.first_id();
        Self {
            config,
            inp: Mutex::new(Pin::new(Box::new(inp))),
            outp: Mutex::new(Pin::new(Box::new(outp))),
            requests: std::sync::Mutex::new(HashMap::new()),
            id: std::sync::Mutex::new(id),
            serializer: protocol::ProtocolSerializer::new(),
            closing: RwLock::new(false),
            capability: RwLock::new(CapabilityData {
                version: 0x00000000,
                capabilities: BTreeSet::new(),
            }),
            authenticated: RwLock::new(false),
            synchronous,
        }
    }

    pub fn authenticated(&self) -> bool {
        let g = self.authenticated.read().unwrap();
        *g
    }

    pub fn set_authenticated(&self, value: bool) {
        let mut g = self.authenticated.write().unwrap();
        *g = value;
    }

    pub fn set_version(&self, version: u32, capabilities: &[protocol::Capability]) {
        let mut g = self.capability.write().unwrap();
        g.version = version;
        g.capabilities = capabilities.iter().cloned().collect();
    }

    pub fn version(&self) -> u32 {
        let g = self.capability.read().unwrap();
        g.version
    }

    pub fn has_capability(&self, capa: &protocol::Capability) -> bool {
        let g = self.capability.read().unwrap();
        g.capabilities.contains(capa)
    }

    pub fn set_capabilities(&self, capa: &BTreeSet<protocol::Capability>) {
        let mut g = self.capability.write().unwrap();
        g.capabilities = capa.iter().cloned().collect()
    }

    pub fn serializer(&self) -> &protocol::ProtocolSerializer {
        &self.serializer
    }

    pub async fn flush_requests(&self) {
        let reqs: HashMap<_, _> = {
            let mut g = self.requests.lock().unwrap();
            g.drain().collect()
        };
        for (_, tx) in reqs {
            let _ = tx.send(Err(Error::Aborted)).await;
        }
    }

    pub async fn close(&self, send_alert: bool) {
        {
            let mut g = self.closing.write().unwrap();
            if *g {
                return;
            }
            *g = true;
        }
        if send_alert {
            let _ = self
                .send_message_simple_internal::<protocol::Empty>(
                    protocol::MessageKind::CloseAlert,
                    true,
                    false,
                )
                .await;
        }
        let sleep = time::sleep(self.config.closing_delay());
        tokio::pin!(sleep);

        loop {
            select! {
                () = &mut sleep => {
                    break;
                }
                _ = self.recv() => {}
            }
        }
    }

    /// Receive one message ore response from the other side.
    ///
    /// Returns `Ok(Some(msg))` if the item read was a message, `Ok(None)` if it was a response
    /// (which we will handle automatically), and `Err` on error.
    pub async fn recv(&self) -> Result<Option<protocol::Message>, Error> {
        let logger = self.config.logger();
        // Hold the lock for the entire duration of reading the message so we don't read partial
        // messages.
        let v = {
            let mut buf = [0u8; 4];
            let mut g = self.inp.lock().await;
            g.as_mut().read_exact(&mut buf).await?;
            let size: u32 = u32::from_le_bytes(buf);
            if !self.serializer.is_valid_size(size) {
                logger.trace(&format!("received invalid packet: size {:08x}", size));
                return Err(Error::Undeserializable);
            }
            let mut v: Vec<u8> = buf.into();
            v.resize(size as usize + 4, 0);
            g.as_mut().read_exact(&mut v[4..]).await?;
            v
        };
        logger.trace(&format!(
            "received packet: size {:08x} id {:08x} next {:08x}",
            u32::from_le_bytes(v[0..4].try_into().unwrap()),
            u32::from_le_bytes(v[4..8].try_into().unwrap()),
            u32::from_le_bytes(v[8..12].try_into().unwrap())
        ));
        dump_packet!(logger, &v);
        match self.serializer.deserialize_data(&self.config, &v)? {
            protocol::Data::Message(m) => {
                logger.trace(&format!(
                    "received message: id {:08x} kind {:08x}",
                    m.id, m.kind
                ));
                Ok(Some(m))
            }
            protocol::Data::Response(r) => {
                logger.trace(&format!(
                    "received response: id {:08x} code {:08x}",
                    r.id, r.code
                ));
                let channel = {
                    let mut g = self.requests.lock().unwrap();
                    g.remove(&r.id)
                };
                if let Some(ch) = channel {
                    logger.trace(&format!("sending response id {:08x} to channel", r.id));
                    let _ = ch.send(Ok(r)).await;
                } else {
                    logger.trace(&format!("nobody waiting on response id {:08x}", r.id));
                }
                Ok(None)
            }
        }
    }

    pub async fn send_success_simple(&self, id: u32) -> Result<(), Error> {
        let r = protocol::Response {
            id,
            code: protocol::ResponseCode::Success as u32,
            message: None,
        };
        match self.serializer.serialize_response_simple(&r) {
            Some(r) => self.send_response(&r).await,
            None => Err(Error::Unserializable),
        }
    }

    pub async fn send_success_typed<S: Serialize>(&self, id: u32, obj: &S) -> Result<(), Error> {
        let r = protocol::Response {
            id,
            code: protocol::ResponseCode::Success as u32,
            message: None,
        };
        match self.serializer.serialize_response_typed(&r, obj) {
            Some(r) => self.send_response(&r).await,
            None => Err(Error::Unserializable),
        }
    }

    pub async fn send_success(&self, id: u32, message: Option<Bytes>) -> Result<(), Error> {
        let logger = self.config.logger();
        let r = protocol::Response {
            id,
            code: protocol::ResponseCode::Success as u32,
            message,
        };
        match self.serializer.serialize_response_simple(&r) {
            Some(r) => {
                logger.trace(&format!(
                    "sending response: size {:08x} id {:08x} next {:08x}",
                    u32::from_le_bytes(r[0..4].try_into().unwrap()),
                    u32::from_le_bytes(r[4..8].try_into().unwrap()),
                    u32::from_le_bytes(r[8..12].try_into().unwrap())
                ));
                self.send_response(&r).await
            }
            None => Err(Error::Unserializable),
        }
    }

    pub async fn send_error_simple(
        &self,
        id: u32,
        kind: protocol::ResponseCode,
    ) -> Result<(), Error> {
        let r = protocol::Response {
            id,
            code: kind as u32,
            message: None,
        };
        match self.serializer.serialize_response_simple(&r) {
            Some(r) => self.send_response(&r).await,
            None => Err(Error::Unserializable),
        }
    }

    pub async fn send_error_typed<S: Serialize>(
        &self,
        id: u32,
        kind: protocol::ResponseCode,
        obj: &S,
    ) -> Result<(), Error> {
        let r = protocol::Response {
            id,
            code: kind as u32,
            message: None,
        };
        match self.serializer.serialize_response_typed(&r, obj) {
            Some(r) => self.send_response(&r).await,
            None => Err(Error::Unserializable),
        }
    }

    pub async fn send_error(
        &self,
        id: u32,
        kind: protocol::ResponseCode,
        message: Option<Bytes>,
    ) -> Result<(), Error> {
        let r = protocol::Response {
            id,
            code: kind as u32,
            message,
        };
        match self.serializer.serialize_response_simple(&r) {
            Some(r) => self.send_response(&r).await,
            None => Err(Error::Unserializable),
        }
    }

    async fn send_response(&self, resp: &Bytes) -> Result<(), Error> {
        {
            let mut g = self.outp.lock().await;
            g.as_mut().write_all(resp).await?
        }
        Ok(())
    }

    pub async fn send_message<S: Serialize, D: DeserializeOwned>(
        &self,
        kind: protocol::MessageKind,
        body: &S,
        synchronous: Option<bool>,
    ) -> Result<Option<D>, Error> {
        let id = {
            let mut g = self.id.lock().unwrap();
            let v = *g;
            *g = self.config.next_id(v);
            v
        };
        let m = protocol::Message {
            id,
            kind: kind as u32,
            message: None,
        };
        let msg = match self.serializer.serialize_message_typed(&m, body) {
            Some(m) => m,
            None => return Err(Error::Unserializable),
        };
        self.send_message_internal(id, &msg, false, synchronous.unwrap_or(self.synchronous))
            .await
    }

    pub async fn send_message_simple<D: DeserializeOwned>(
        &self,
        kind: protocol::MessageKind,
        synchronous: Option<bool>,
    ) -> Result<Option<D>, Error> {
        self.send_message_simple_internal(kind, false, synchronous.unwrap_or(self.synchronous))
            .await
    }

    async fn send_message_simple_internal<D: DeserializeOwned>(
        &self,
        kind: protocol::MessageKind,
        closing: bool,
        synchronous: bool,
    ) -> Result<Option<D>, Error> {
        let id = {
            let mut g = self.id.lock().unwrap();
            let v = *g;
            *g = self.config.next_id(v);
            v
        };
        let logger = self.config.logger();
        logger.trace(&format!("simple message: id {:08x} kind {:?}", id, kind));
        let m = protocol::Message {
            id,
            kind: kind as u32,
            message: None,
        };
        logger.trace(&format!(
            "simple message: id {:08x} kind {:08x}",
            m.id, m.kind
        ));
        let msg = match self.serializer.serialize_message_simple(&m) {
            Some(m) => m,
            None => return Err(Error::Unserializable),
        };
        self.send_message_internal(id, &msg, closing, synchronous)
            .await
    }

    async fn send_message_internal<D: DeserializeOwned>(
        &self,
        id: u32,
        data: &Bytes,
        closing: bool,
        synchronous: bool,
    ) -> Result<Option<D>, Error> {
        let logger = self.config.logger();
        if !closing {
            let g = self.closing.read().unwrap();
            if *g {
                return Err(Error::Aborted);
            }
        }
        logger.trace(&format!(
            "sending message: size {:08x} id {:08x} kind {:08x}",
            u32::from_le_bytes(data[0..4].try_into().unwrap()),
            u32::from_le_bytes(data[4..8].try_into().unwrap()),
            u32::from_le_bytes(data[8..12].try_into().unwrap())
        ));
        dump_packet!(logger, &data);
        let (sender, mut receiver) = channel(1);
        let max_messages = self.config.max_messages_in_flight();
        let reject = {
            let mut g = self.requests.lock().unwrap();
            if g.len() >= max_messages as usize {
                true
            } else {
                g.insert(id, sender);
                false
            }
        };
        if reject {
            let _ = self
                .send_error_simple(id, protocol::ResponseCode::TooManyMessages)
                .await;
            return Err(Error::TooManyMessages);
        }
        {
            let mut g = self.outp.lock().await;
            g.as_mut().write_all(data).await?;
        }
        if synchronous {
            logger.trace("synchronous mode: waiting for response");
            loop {
                match self.recv().await {
                    Ok(None) => {
                        logger.trace("synchronous mode: got response");
                        break;
                    }
                    Err(e) => {
                        logger.trace(&format!("synchronous mode: got error {}", e));
                        return Err(e);
                    }
                    Ok(Some(m)) => {
                        logger.trace(&format!("synchronous mode: got unrelated message {:?}", m));
                    }
                }
            }
        }
        let m = match receiver.recv().await {
            Some(Ok(m)) => m,
            Some(Err(e)) => return Err(e),
            None => return Err(Error::NoResponseReceived),
        };
        match self.serializer.deserialize_response_typed(&m) {
            Ok(resp) => Ok(resp),
            Err(e) => Err(e.into()),
        }
    }
}
