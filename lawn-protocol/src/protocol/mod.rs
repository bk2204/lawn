#![allow(non_upper_case_globals)]
use crate::config::Config;
use bitflags::bitflags;
use bytes::{Bytes, BytesMut};
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io;

/// # Overview
///
/// The protocol is relatively simple.  Each request consists of a 32-bit size of the resulting
/// message, a 32-bit request ID, a 32-bit message type, and an optional per-message CBOR blob
/// representing message data.  For performance and security reasons, the message size is limited
/// to 2^24 in size.  The size includes all fields other than the size.
///
/// Each response consists of a 32-bit size of the message, the 32-bit request ID, a 32-bit
/// response code, and an optional per-response code CBOR blob.
///
/// The bottom 31 bits of the request ID may be any value; the response will use the same ID.  No
/// check is made for duplicates, so the requestor should prefer not repeating IDs that are in
/// flight.  The top bit is clear if the request is client-to-server request and it is set if the
/// request is a server-to-client request.  This helps eliminate confusion as to whether a message
/// is a request or a response.
///
/// All data is serialized in a little-endian format.

/// The response codes for the protocol.
///
/// The response codes are based around IMAP's response codes, and the top two bytes of the
/// response indicates the type:
///
/// * 0: success
/// * 1: no (roughly, the request was understood, but not completed)
/// * 2: bad (roughly, the request was not understood)
#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum ResponseCode {
    /// The request was successful.  The response contains the requested data.
    Success = 0x00000000,
    /// The request is incomplete, but is so far successful.  The request should continue,
    /// referencing the ID of the last request.
    Continuation = 0x00000001,

    /// The request requires authentication.
    ///
    /// The semantics for this message are equivalent to an HTTP 401 response.
    NeedsAuthentication = 0x00010000,
    /// The message was not allowed.
    ///
    /// The semantics for this message are equivalent to an HTTP 403 response.
    Forbidden = 0x00010001,
    /// The server is shutting down.
    Closing = 0x00010002,
    /// The message failed for a system error reason.
    ///
    /// This is generally only useful for certain types of channels.
    Errno = 0x00010003,
    AuthenticationFailed = 0x00010004,
    /// The other end of the channel has disappeared.
    Gone = 0x00010005,
    NotFound = 0x00010006,
    InternalError = 0x00010007,
    /// The channel has ceased to produce new data and this operation cannot complete.
    ChannelDead = 0x00010008,

    /// The message type was not enabled.
    NotEnabled = 0x00020000,
    /// The message type was not supported.
    NotSupported = 0x00020001,
    /// The parameters were not supported.
    ParametersNotSupported = 0x00020002,
    /// The message type was received, but was not valid.
    Invalid = 0x00020003,
    /// The message was too large.
    TooLarge = 0x00020004,
    /// There are too many pending messages.
    TooManyMessages = 0x00020005,
    /// The parameters are supported, but not correct.
    ///
    /// For example, if a selector is not valid for a channel, this message may be sent.
    InvalidParameters = 0x00020006,
}

impl ResponseCode {
    fn from_u32(val: u32) -> Self {
        FromPrimitive::from_u32(val).unwrap_or(Self::Invalid)
    }
}

pub struct WrongTypeError;

#[derive(Debug, Clone)]
pub struct Error {
    pub code: ResponseCode,
    pub body: Option<ErrorBody>,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn from_errno(err: i32) -> Error {
        io::Error::from_raw_os_error(err).into()
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        let lerr: lawn_errno::Error = err.into();
        Error {
            code: ResponseCode::Errno,
            body: Some(ErrorBody::Errno(Errno { errno: lerr as u32 })),
        }
    }
}

impl From<ResponseCode> for Error {
    fn from(code: ResponseCode) -> Error {
        Error { code, body: None }
    }
}

impl TryInto<io::Error> for Error {
    type Error = WrongTypeError;
    fn try_into(self) -> Result<io::Error, Self::Error> {
        if self.code == ResponseCode::Errno {
            if let Some(ErrorBody::Errno(Errno { errno })) = self.body {
                if let Some(e) = lawn_errno::Error::from_u32(errno) {
                    return Ok(e.into());
                }
            }
        }
        Err(WrongTypeError)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Empty {}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct Errno {
    errno: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(untagged)]
pub enum ErrorBody {
    Errno(Errno),
    Exit(i32),
}

#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum MessageKind {
    /// Requests that the other side provide a list of supported versions and capabilities.
    Capability = 0x00000000,
    /// Requests a specific version and capabilities.
    ///
    /// This request aborts all other in-flight requests by this sender.  Consequently, it should
    /// be sent at the beginning of the connection right after a successful `Capability` message.
    ///
    /// Authentication is not required for this message.
    Version = 0x00000001,
    /// Indicates a no-op request which should always be successful.
    ///
    /// Authentication is not required for this message.
    Ping = 0x00000002,
    /// Requests authentication.
    ///
    /// This request aborts all other in-flight requests by this sender.  Consequently, it should
    /// be sent at the beginning of the connection right after a successful `Capability` message.
    ///
    /// Authentication is not required for this message (obviously).
    Authenticate = 0x00000003,

    /// Indicates a graceful shutdown.
    ///
    /// Authentication is not required for this message.
    CloseAlert = 0x00001000,

    /// Requests a channel to be created.
    CreateChannel = 0x00010000,
    /// Requests a channel to be deleted.
    ///
    /// This request is made from the client to the server to terminate the connection.
    DeleteChannel = 0x00010001,
    /// Requests a read on the channel.
    ReadChannel = 0x00010002,
    /// Requests a write on the channel.
    WriteChannel = 0x00010003,
    /// Requests the status of the selectors on the channel.
    PollChannel = 0x00010004,
    /// Requests the status of the object on the other end of the channel.
    ///
    /// For command channels, this can be used to check if the child has exited.
    PingChannel = 0x00010005,
    // Not implemented:
    // AttachChannelSelector = 0x00010010,
    DetachChannelSelector = 0x00010011,
    /// Provides notification of some sort of metadata condition on the channel.
    ///
    /// For command channels, this is used by the server to notify the client that the process has
    /// terminated.
    ChannelMetadataNotification = 0x00011000,
}

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
pub enum Capability {
    AuthExternal,
    ChannelCommand,
    Channel9P,
}

impl Capability {
    pub fn implemented() -> BTreeSet<Capability> {
        [Self::AuthExternal, Self::ChannelCommand]
            .iter()
            .cloned()
            .collect()
    }

    pub fn is_implemented(&self) -> bool {
        match self {
            Self::AuthExternal | Self::ChannelCommand => true,
            _ => false,
        }
    }
}

impl From<Capability> for (&'static [u8], Option<&'static [u8]>) {
    fn from(capa: Capability) -> (&'static [u8], Option<&'static [u8]>) {
        match capa {
            Capability::AuthExternal => (b"auth", Some(b"EXTERNAL")),
            Capability::ChannelCommand => (b"channel", Some(b"command")),
            Capability::Channel9P => (b"channel", Some(b"9p")),
        }
    }
}

impl From<Capability> for (Bytes, Option<Bytes>) {
    fn from(capa: Capability) -> (Bytes, Option<Bytes>) {
        let (a, b): (&'static [u8], Option<&'static [u8]>) = capa.into();
        (a.into(), b.map(|x| x.into()))
    }
}

impl TryFrom<(&[u8], Option<&[u8]>)> for Capability {
    type Error = ();
    fn try_from(data: (&[u8], Option<&[u8]>)) -> Result<Capability, ()> {
        match data {
            (b"auth", Some(b"EXTERNAL")) => Ok(Capability::AuthExternal),
            (b"channel", Some(b"command")) => Ok(Capability::ChannelCommand),
            (b"channel", Some(b"9p")) => Ok(Capability::Channel9P),
            _ => Err(()),
        }
    }
}

impl TryFrom<(Bytes, Option<Bytes>)> for Capability {
    type Error = ();
    fn try_from(data: (Bytes, Option<Bytes>)) -> Result<Capability, ()> {
        match data {
            (a, Some(b)) => (&a as &[u8], Some(&b as &[u8])).try_into(),
            (a, None) => (&a as &[u8], None).try_into(),
        }
    }
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct CapabilityResponse {
    pub version: Vec<u32>,
    pub capabilities: Vec<(Bytes, Option<Bytes>)>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct VersionRequest {
    pub version: u32,
    pub enable: Vec<(Bytes, Option<Bytes>)>,
    pub id: Option<Bytes>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct AuthenticateRequest {
    pub last_id: Option<u32>,
    // All uppercase methods are SASL methods as defined by IANA.  Other methods are defined
    // internally.
    pub method: Bytes,
    pub message: Option<Bytes>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct AuthenticateResponse {
    // All uppercase methods are SASL methods as defined by IANA.  Other methods are defined
    // internally.
    pub method: Bytes,
    pub message: Option<Bytes>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
pub struct ChannelID(pub u32);

impl fmt::Display for ChannelID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
pub struct ChannelSelectorID(pub u32);

/// A message to create a channel.
///
/// The following channel types are known:
///
/// * `command`: Invoke a command on the remote side.  `args` is the command-line arguments and
///   `env` is the environment.
/// * `9p`: Create a channel implementing the 9p2000.L protocol.  `args[0]` is the desired mount
///   point as specified by the server.
///
/// Custom channel types can be created with an at sign and domain name representing the custom
/// extension.
#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct CreateChannelRequest {
    pub kind: Bytes,
    pub kind_args: Option<Vec<Bytes>>,
    pub args: Option<Vec<Bytes>>,
    pub env: Option<BTreeMap<Bytes, Bytes>>,
    pub meta: Option<BTreeMap<Bytes, Value>>,
    pub selectors: Vec<u32>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct CreateChannelResponse {
    pub id: ChannelID,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct DeleteChannelRequest {
    pub id: ChannelID,
    pub termination: Option<u32>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct ReadChannelRequest {
    pub id: ChannelID,
    pub selector: u32,
    pub count: u64,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct ReadChannelResponse {
    pub bytes: Bytes,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct WriteChannelRequest {
    pub id: ChannelID,
    pub selector: u32,
    pub bytes: Bytes,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct WriteChannelResponse {
    pub count: u64,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct DetachChannelSelectorRequest {
    pub id: ChannelID,
    pub selector: u32,
}

bitflags! {
    #[derive(Default)]
    pub struct PollChannelFlags: u64 {
        const Input   = 0x00000001;
        const Output  = 0x00000002;
        const Error   = 0x00000004;
        const Hangup  = 0x00000008;
        const Invalid = 0x00000010;
        const Gone    = 0x00000020;
    }
}

#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum ChannelMetadataNotificationKind {
    WaitStatus = 0,
}

#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum ChannelMetadataStatusKind {
    Exited = 0,
    Signalled = 1,
    SignalledWithCore = 2,
    Stopped = 3,
    Unknown = 0x7fffffff,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct PingChannelRequest {
    pub id: ChannelID,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct PollChannelRequest {
    pub id: ChannelID,
    pub selectors: Vec<u32>,
    pub milliseconds: Option<u32>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct PollChannelResponse {
    pub id: ChannelID,
    pub selectors: BTreeMap<u32, u64>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct ChannelMetadataNotification {
    pub id: ChannelID,
    pub kind: u32,
    pub status: Option<u32>,
    pub status_kind: Option<u32>,
    pub meta: Option<BTreeMap<Bytes, Value>>,
}

/// A message for the protocol.
#[derive(Clone, Debug)]
pub struct Message {
    pub id: u32,
    pub kind: u32,
    pub message: Option<Bytes>,
}

#[derive(Clone, Debug)]
pub struct Response {
    pub id: u32,
    pub code: u32,
    pub message: Option<Bytes>,
}

pub struct ProtocolSerializer {}

pub enum Data {
    Message(Message),
    Response(Response),
}

impl ProtocolSerializer {
    const MAX_MESSAGE_SIZE: u32 = 0x00ffffff;

    pub fn new() -> ProtocolSerializer {
        Self {}
    }

    pub fn is_valid_size(&self, size: u32) -> bool {
        size >= 8 && size <= Self::MAX_MESSAGE_SIZE
    }

    pub fn serialize_message_simple(&self, msg: &Message) -> Option<Bytes> {
        let mut b = BytesMut::new();
        let size = 8 + match &msg.message {
            Some(m) => m.len(),
            None => 0,
        };
        if size > Self::MAX_MESSAGE_SIZE as usize {
            return None;
        }
        let size = size as u32;
        b.extend(&size.to_le_bytes());
        b.extend(&msg.id.to_le_bytes());
        b.extend(&msg.kind.to_le_bytes());
        match &msg.message {
            Some(m) => b.extend(m),
            None => (),
        };
        Some(b.into())
    }

    pub fn serialize_message_typed<S: Serialize>(&self, msg: &Message, obj: &S) -> Option<Bytes> {
        let mut m = msg.clone();
        let body = match serde_cbor::to_vec(obj) {
            Ok(m) => m,
            Err(_) => return None,
        };
        m.message = Some(body.into());
        self.serialize_message_simple(&m)
    }

    pub fn serialize_body<S: Serialize>(&self, obj: &S) -> Option<Bytes> {
        match serde_cbor::to_vec(obj) {
            Ok(m) => Some(m.into()),
            Err(_) => None,
        }
    }

    pub fn serialize_response_simple(&self, resp: &Response) -> Option<Bytes> {
        let mut b = BytesMut::new();
        let size = 8 + match &resp.message {
            Some(m) => m.len(),
            None => 0,
        };
        if size > Self::MAX_MESSAGE_SIZE as usize {
            return None;
        }
        let size = size as u32;
        b.extend(&size.to_le_bytes());
        b.extend(&resp.id.to_le_bytes());
        b.extend(&resp.code.to_le_bytes());
        match &resp.message {
            Some(m) => b.extend(m),
            None => (),
        };
        Some(b.into())
    }

    pub fn serialize_response_typed<S: Serialize>(&self, msg: &Response, obj: &S) -> Option<Bytes> {
        let mut m = msg.clone();
        let body = match serde_cbor::to_vec(obj) {
            Ok(m) => m,
            Err(_) => return None,
        };
        m.message = Some(body.into());
        self.serialize_response_simple(&m)
    }

    pub fn deserialize_data(&self, config: &Config, data: &[u8]) -> Result<Data, Error> {
        fn is_sender(config: &Config, id: u32) -> bool {
            let sender_mask = if config.is_server() { 0x80000000 } else { 0 };
            (id & 0x80000000) == sender_mask
        }
        let _size: u32 = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let id: u32 = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let arg: u32 = u32::from_le_bytes(data[8..12].try_into().unwrap());
        if is_sender(config, id) {
            Ok(Data::Response(Response {
                id,
                code: arg,
                message: if data.len() == 12 {
                    None
                } else {
                    Some(data[12..].to_vec().into())
                },
            }))
        } else {
            Ok(Data::Message(Message {
                id,
                kind: arg,
                message: if data.len() == 12 {
                    None
                } else {
                    Some(data[12..].to_vec().into())
                },
            }))
        }
    }

    pub fn deserialize_message_typed<'a, D: Deserialize<'a>>(
        &self,
        msg: &'a Message,
    ) -> Result<Option<D>, Error> {
        match &msg.message {
            Some(body) => match serde_cbor::from_slice(body) {
                Ok(decoded) => Ok(Some(decoded)),
                Err(_) => Err(Error {
                    code: ResponseCode::Invalid,
                    body: None,
                }),
            },
            None => Ok(None),
        }
    }

    pub fn deserialize_response_typed<'a, D: Deserialize<'a>>(
        &self,
        resp: &'a Response,
    ) -> Result<Option<D>, Error> {
        if resp.code == ResponseCode::Success as u32 {
            match &resp.message {
                Some(body) => match serde_cbor::from_slice(body) {
                    Ok(decoded) => Ok(Some(decoded)),
                    Err(_) => Err(Error {
                        code: ResponseCode::Invalid,
                        body: None,
                    }),
                },
                None => Ok(None),
            }
        } else {
            match &resp.message {
                Some(body) => match serde_cbor::from_slice(body) {
                    Ok(decoded) => Err(Error {
                        code: ResponseCode::from_u32(resp.code),
                        body: Some(decoded),
                    }),
                    Err(_) => Err(Error {
                        code: ResponseCode::from_u32(resp.code),
                        body: None,
                    }),
                },
                None => Err(Error {
                    code: ResponseCode::from_u32(resp.code),
                    body: None,
                }),
            }
        }
    }
}
