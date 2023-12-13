use crate::config::Config;
use crate::protocol;
use bytes::{Bytes, BytesMut};
use lawn_constants::trace;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;
use std::io;
use std::marker::Unpin;
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::select;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::{Mutex, RwLock};
use tokio::time;

macro_rules! dump_packet {
    ($logger:expr, $arg:expr) => {{
        use crate::config::LogLevel;
        if $logger.level() <= LogLevel::Dump {
            $logger.trace(&format!("packet: {}", hex::encode($arg)));
        }
    }};
    ($logger:expr, $header:expr, $body:expr) => {{
        use crate::config::LogLevel;
        if $logger.level() <= LogLevel::Dump {
            $logger.trace(&format!(
                "packet: {}{}",
                hex::encode($header),
                hex::encode($body)
            ));
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

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ExtensionError {
    NoSpace,
    RangeTooLarge,
    RangeInUse,
    WrongExtension,
    NoSuchRange,
    NoSuchKind,
    NotExtensionMessage,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ExtensionData {
    pub extension: (Bytes, Option<Bytes>),
    pub base: u32,
    pub count: u32,
}

pub struct ExtensionMapIter<'a> {
    iter: std::collections::btree_map::Iter<'a, u32, ExtensionData>,
}

impl<'a> Iterator for ExtensionMapIter<'a> {
    type Item = (RangeInclusive<u32>, &'a ExtensionData);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .map(|(_, e)| (e.base..=e.base + e.count, e))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

#[derive(Default, Debug, Clone)]
pub struct ExtensionMap {
    map: BTreeMap<u32, ExtensionData>,
}

impl ExtensionMap {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        base: Option<u32>,
        extension: (Bytes, Option<Bytes>),
        count: u32,
    ) -> Result<u32, ExtensionError> {
        if count > 0x1000 {
            return Err(ExtensionError::RangeTooLarge);
        }
        let base = match base {
            Some(base) => {
                if !Self::is_extension_message(base) {
                    return Err(ExtensionError::NotExtensionMessage);
                }
                if self.map.contains_key(&base) {
                    return Err(ExtensionError::RangeInUse);
                }
                base
            }
            None => {
                let base = (0..=0xfff)
                    .map(|bits| 0xff000000 | (bits << 12))
                    .find(|bottom| !self.map.contains_key(bottom));
                match base {
                    Some(base) => base,
                    None => return Err(ExtensionError::NoSpace),
                }
            }
        };
        self.map.insert(
            base,
            ExtensionData {
                extension,
                base,
                count,
            },
        );
        Ok(base)
    }

    pub fn remove(
        &mut self,
        base: u32,
        extension: (Bytes, Option<Bytes>),
    ) -> Result<(), ExtensionError> {
        let ext = self.map.get(&base).map(|e| e.extension.clone());
        if let Some(ext) = ext {
            if ext == extension {
                self.map.remove(&base);
                Ok(())
            } else {
                Err(ExtensionError::WrongExtension)
            }
        } else {
            Err(ExtensionError::NoSuchRange)
        }
    }

    pub fn is_extension_message(kind: u32) -> bool {
        (kind & 0xff000000) == 0xff000000
    }

    pub fn find(&self, kind: u32) -> Result<((Bytes, Option<Bytes>), u32), ExtensionError> {
        if !Self::is_extension_message(kind) {
            // This is not in the extension range.
            return Err(ExtensionError::NotExtensionMessage);
        }
        let base = kind & 0xfffff000;
        match self.map.get(&base) {
            Some(entry) => {
                let offset = kind & 0x00000fff;
                if offset < entry.count {
                    Ok((entry.extension.clone(), offset))
                } else {
                    Err(ExtensionError::NoSuchKind)
                }
            }
            None => Err(ExtensionError::NoSuchKind),
        }
    }

    pub fn iter(&self) -> ExtensionMapIter<'_> {
        ExtensionMapIter {
            iter: self.map.iter(),
        }
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
    requests: tokio::sync::Mutex<HashMap<u32, Sender<Result<protocol::Response, Error>>>>,
    id: tokio::sync::Mutex<u32>,
    serializer: protocol::ProtocolSerializer,
    closing: tokio::sync::RwLock<bool>,
    capability: tokio::sync::RwLock<CapabilityData>,
    authenticated: tokio::sync::RwLock<bool>,
    synchronous: bool,
}

impl<T: AsyncRead + Unpin, U: AsyncWrite + Unpin> ProtocolHandler<T, U> {
    pub fn new(config: Arc<Config>, inp: T, outp: U, synchronous: bool) -> Self {
        let id = config.first_id();
        Self {
            config,
            inp: Mutex::new(Pin::new(Box::new(inp))),
            outp: Mutex::new(Pin::new(Box::new(outp))),
            requests: tokio::sync::Mutex::new(HashMap::new()),
            id: tokio::sync::Mutex::new(id),
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

    pub async fn authenticated(&self) -> bool {
        let g = self.authenticated.read().await;
        *g
    }

    pub async fn set_authenticated(&self, value: bool) {
        let mut g = self.authenticated.write().await;
        *g = value;
    }

    pub fn set_version(&self, version: u32, capabilities: &[protocol::Capability]) {
        let mut g = self.capability.blocking_write();
        g.version = version;
        g.capabilities = capabilities.iter().cloned().collect();
    }

    pub fn version(&self) -> u32 {
        let g = self.capability.blocking_read();
        g.version
    }

    pub async fn has_capability(&self, capa: &protocol::Capability) -> bool {
        let g = self.capability.read().await;
        g.capabilities.contains(capa)
    }

    #[allow(clippy::mutable_key_type)]
    pub async fn set_capabilities(&self, capa: &BTreeSet<protocol::Capability>) {
        let mut g = self.capability.write().await;
        g.capabilities = capa.iter().cloned().collect()
    }

    pub fn serializer(&self) -> &protocol::ProtocolSerializer {
        &self.serializer
    }

    pub async fn flush_requests(&self) {
        let reqs: HashMap<_, _> = {
            let mut g = self.requests.lock().await;
            g.drain().collect()
        };
        for (_, tx) in reqs {
            let _ = tx.send(Err(Error::Aborted)).await;
        }
    }

    pub async fn close(&self, send_alert: bool) {
        {
            let mut g = self.closing.write().await;
            if *g {
                return;
            }
            *g = true;
        }
        if send_alert {
            let _ = self
                .send_message_simple_internal::<protocol::Empty, protocol::Empty>(
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
    pub async fn recv(&self) -> Result<Option<Box<protocol::Message>>, Error> {
        let logger = self.config.logger();
        // Hold the lock for the entire duration of reading the message so we don't read partial
        // messages.
        let (header, body) = {
            let mut buf = [0u8; 12];
            let mut g = self.inp.lock().await;
            g.as_mut().read_exact(&mut buf).await?;
            let size: u32 = u32::from_le_bytes(buf[0..4].try_into().unwrap());
            if !self.serializer.is_valid_size(size) {
                trace!(logger, "received invalid packet: size {:08x}", size);
                return Err(Error::Undeserializable);
            }
            let mut b = BytesMut::new();
            b.resize(size as usize - 8, 0);
            g.as_mut().read_exact(&mut b).await?;
            (buf, b.into())
        };
        logger.trace(&format!(
            "received packet: size {:08x} id {:08x} next {:08x}",
            u32::from_le_bytes(header[0..4].try_into().unwrap()),
            u32::from_le_bytes(header[4..8].try_into().unwrap()),
            u32::from_le_bytes(header[8..12].try_into().unwrap())
        ));
        dump_packet!(logger, &header, &body);
        match self
            .serializer
            .deserialize_data(&self.config, &header, body)?
        {
            protocol::Data::Message(m) => {
                trace!(
                    logger,
                    "received message: id {:08x} kind {:08x}",
                    m.id,
                    m.kind
                );
                Ok(Some(Box::new(m)))
            }
            protocol::Data::Response(r) => {
                trace!(
                    logger,
                    "received response: id {:08x} code {:08x}",
                    r.id,
                    r.code
                );
                let channel = {
                    let mut g = self.requests.lock().await;
                    g.remove(&r.id)
                };
                if let Some(ch) = channel {
                    trace!(logger, "sending response id {:08x} to channel", r.id);
                    let _ = ch.send(Ok(r)).await;
                } else {
                    trace!(logger, "nobody waiting on response id {:08x}", r.id);
                }
                Ok(None)
            }
        }
    }

    pub async fn send_success_simple(&self, id: u32) -> Result<(), Error> {
        match self
            .serializer
            .serialize_header(id, protocol::ResponseCode::Success as u32, 0)
        {
            Some(r) => self.send_response(Some(r), None).await,
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
            Some(r) => self.send_response(None, Some(r)).await,
            None => Err(Error::Unserializable),
        }
    }

    pub async fn send_success(&self, id: u32, message: Option<Bytes>) -> Result<(), Error> {
        let logger = self.config.logger();
        match self.serializer.serialize_header(
            id,
            protocol::ResponseCode::Success as u32,
            message.as_ref().map(|m| m.len()).unwrap_or_default(),
        ) {
            Some(r) => {
                trace!(
                    logger,
                    "sending response: size {:08x} id {:08x} next {:08x}",
                    u32::from_le_bytes(r[0..4].try_into().unwrap()),
                    u32::from_le_bytes(r[4..8].try_into().unwrap()),
                    u32::from_le_bytes(r[8..12].try_into().unwrap())
                );
                self.send_response(Some(r), message).await
            }
            None => Err(Error::Unserializable),
        }
    }

    pub async fn send_continuation(&self, id: u32, message: Option<Bytes>) -> Result<(), Error> {
        let logger = self.config.logger();
        match self.serializer.serialize_header(
            id,
            protocol::ResponseCode::Continuation as u32,
            message.as_ref().map(|m| m.len()).unwrap_or_default(),
        ) {
            Some(r) => {
                trace!(
                    logger,
                    "sending response: size {:08x} id {:08x} next {:08x}",
                    u32::from_le_bytes(r[0..4].try_into().unwrap()),
                    u32::from_le_bytes(r[4..8].try_into().unwrap()),
                    u32::from_le_bytes(r[8..12].try_into().unwrap())
                );
                self.send_response(Some(r), message).await
            }
            None => Err(Error::Unserializable),
        }
    }

    pub async fn send_error_simple(
        &self,
        id: u32,
        kind: protocol::ResponseCode,
    ) -> Result<(), Error> {
        match self.serializer.serialize_header(id, kind as u32, 0) {
            Some(r) => self.send_response(Some(r), None).await,
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
            Some(r) => self.send_response(None, Some(r)).await,
            None => Err(Error::Unserializable),
        }
    }

    pub async fn send_error(
        &self,
        id: u32,
        kind: protocol::ResponseCode,
        message: Option<Bytes>,
    ) -> Result<(), Error> {
        match self.serializer.serialize_header(
            id,
            kind as u32,
            message.as_ref().map(|m| m.len()).unwrap_or_default(),
        ) {
            Some(r) => self.send_response(Some(r), message).await,
            None => Err(Error::Unserializable),
        }
    }

    async fn send_response(&self, header: Option<Bytes>, resp: Option<Bytes>) -> Result<(), Error> {
        {
            let mut g = self.outp.lock().await;
            if let Some(b) = header {
                g.as_mut().write_all(&b).await?;
            }
            if let Some(r) = resp {
                g.as_mut().write_all(&r).await?;
            }
        }
        Ok(())
    }

    pub async fn send_message<S: Serialize, D1: DeserializeOwned, D2: DeserializeOwned>(
        &self,
        kind: protocol::MessageKind,
        body: &S,
        synchronous: Option<bool>,
    ) -> Result<Option<protocol::ResponseValue<D1, D2>>, Error> {
        self.send_message_with_id(kind, body, synchronous)
            .await
            .map(|v| v.1)
    }

    pub async fn send_message_with_id<S: Serialize, D1: DeserializeOwned, D2: DeserializeOwned>(
        &self,
        kind: protocol::MessageKind,
        body: &S,
        synchronous: Option<bool>,
    ) -> Result<(u32, Option<protocol::ResponseValue<D1, D2>>), Error> {
        let id = {
            let mut g = self.id.lock().await;
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

    pub async fn send_message_simple<D1: DeserializeOwned, D2: DeserializeOwned>(
        &self,
        kind: protocol::MessageKind,
        synchronous: Option<bool>,
    ) -> Result<Option<protocol::ResponseValue<D1, D2>>, Error> {
        self.send_message_simple_internal(kind, false, synchronous.unwrap_or(self.synchronous))
            .await
            .map(|v| v.1)
    }

    pub async fn send_message_simple_with_id<D1: DeserializeOwned, D2: DeserializeOwned>(
        &self,
        kind: protocol::MessageKind,
        synchronous: Option<bool>,
    ) -> Result<(u32, Option<protocol::ResponseValue<D1, D2>>), Error> {
        self.send_message_simple_internal(kind, false, synchronous.unwrap_or(self.synchronous))
            .await
    }

    async fn send_message_simple_internal<D1: DeserializeOwned, D2: DeserializeOwned>(
        &self,
        kind: protocol::MessageKind,
        closing: bool,
        synchronous: bool,
    ) -> Result<(u32, Option<protocol::ResponseValue<D1, D2>>), Error> {
        let id = {
            let mut g = self.id.lock().await;
            let v = *g;
            *g = self.config.next_id(v);
            v
        };
        let logger = self.config.logger();
        trace!(logger, "simple message: id {:08x} kind {:?}", id, kind);
        let m = protocol::Message {
            id,
            kind: kind as u32,
            message: None,
        };
        trace!(
            logger,
            "simple message: id {:08x} kind {:08x}",
            m.id,
            m.kind
        );
        let msg = match self.serializer.serialize_message_simple(&m) {
            Some(m) => m,
            None => return Err(Error::Unserializable),
        };
        self.send_message_internal(id, &msg, closing, synchronous)
            .await
    }

    async fn send_message_internal<D1: DeserializeOwned, D2: DeserializeOwned>(
        &self,
        id: u32,
        data: &Bytes,
        closing: bool,
        synchronous: bool,
    ) -> Result<(u32, Option<protocol::ResponseValue<D1, D2>>), Error> {
        let logger = self.config.logger();
        if !closing {
            let g = self.closing.read().await;
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
            let mut g = self.requests.lock().await;
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
            trace!(logger, "synchronous mode: waiting for response");
            loop {
                match self.recv().await {
                    Ok(None) => {
                        trace!(logger, "synchronous mode: got response");
                        break;
                    }
                    Err(e) => {
                        trace!(logger, "synchronous mode: got error {}", e);
                        return Err(e);
                    }
                    Ok(Some(m)) => {
                        trace!(logger, "synchronous mode: got unrelated message {:?}", m);
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
            Ok(resp) => Ok((id, resp)),
            Err(e) => Err(e.into()),
        }
    }
}
