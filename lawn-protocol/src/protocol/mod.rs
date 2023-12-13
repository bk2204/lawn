#![allow(non_upper_case_globals)]
use crate::config::Config;
use bitflags::bitflags;
use bytes::{Bytes, BytesMut};
use num_traits::FromPrimitive;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io;
use std::io::{Seek, SeekFrom};

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
///
/// ## Extension Messages
///
/// Extension values (message types and response codes) are assigned with
/// values `0xff000000` and larger.  These can be dynamically allocated using
/// the `CreateExtensionRange` message, and once allocated, will allow the
/// extension to use the given codes both as message types and response codes.
///
/// Note that an implementation is not obligated to allocate or use extension
/// codes.  For example, an implementation which offers a new sort of channel may
/// well choose to use the existing channel codes, or it may choose to use new
/// message types with existing response codes.
///
/// Lawn currently allocates these by allocating a 12-bit range internally, so
/// the first code of the first extension is `0xff000000`, the first code of the next is
/// `0xfff001000`,  and so on.  This provides 4096 codes per extension while
/// allowing 4096 extensions.  However, this algorithm is subject to change at any
/// time.

/// The response codes for the protocol.
///
/// The response codes are based around IMAP's response codes, and the top two bytes of the
/// response indicates the type:
///
/// * 00: success
/// * 01: no (roughly, the request was understood, but not completed)
/// * 02: bad (roughly, the request was not understood)
/// * ff: extension message (dynamically allocated)
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
    /// The operation was aborted.
    Aborted = 0x00010009,
    /// There is no continuation with the specified parameters.
    ContinuationNotFound = 0x0001000a,
    /// The result was out of range.
    ///
    /// The semantics for this message are equivalent to `ERANGE`.
    OutOfRange = 0x0001000b,
    /// There is no more space for the requested item.
    NoSpace = 0x0001000c,
    /// The requested operation would conflict with something already existing.
    ///
    /// The semantics for this message are equivalent to an HTTP 409 response.
    Conflict = 0x0001000d,
    /// The contents of the object cannot be listed or specified by name.
    ///
    /// For example, when using a Git-protocol credential helper, it is not possible to enumerate
    /// all credentials or pick a credential by ID.
    Unlistable = 0x0001000e,

    /// The message type was not enabled.
    NotEnabled = 0x00020000,
    /// The message type or operation was not supported.
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

pub struct WrongTypeError(pub Error);

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
        let lerr: lawn_constants::Error = err.into();
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
                if let Some(e) = lawn_constants::Error::from_u32(errno) {
                    return Ok(e.into());
                }
            }
        }
        Err(WrongTypeError(self))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
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

#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
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
    /// Continue an in-progress request.
    ///
    /// This request can be used to continue an operation when the `Continuation` response is
    /// provided.
    Continue = 0x00000004,
    /// Abort an in-progress request.
    ///
    /// This request can be used to abort an operation when the `Continuation` response is
    /// provided.
    Abort = 0x00000005,

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

    /// Allocates a range of IDs for an extension.
    CreateExtensionRange = 0x00020000,

    /// Deallocates a range of IDs for an extension.
    DeleteExtensionRange = 0x00020001,

    /// Lists all allocated ranges of IDs for extensions.
    ListExtensionRanges = 0x00020002,

    /// Open a store and associate an ID with it.
    OpenStore = 0x00030000,

    /// Close a store and associate an ID with it.
    CloseStore = 0x00030001,

    /// Lists all elements of a given type in the given store.
    ListStoreElements = 0x00030002,

    /// Acquire a handle to an element in the given store.
    AcquireStoreElement = 0x00030003,

    /// Release the handle of a store element.
    CloseStoreElement = 0x00030004,

    /// Authenticate to a store element if that's required to open it.
    AuthenticateStoreElement = 0x00030005,

    /// Create a store element.
    CreateStoreElement = 0x00030006,

    /// Delete a store element.
    DeleteStoreElement = 0x00030007,

    /// Update a store element.
    UpdateStoreElement = 0x00030008,

    /// Read a store element.
    ReadStoreElement = 0x00030009,

    /// Rename a store element.
    RenameStoreElement = 0x0003000a,

    /// Copy a store element.
    CopyStoreElement = 0x0003000b,

    /// Search store elements.
    SearchStoreElements = 0x0003000c,
}

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub enum Capability {
    AuthExternal,
    AuthKeyboardInteractive,
    AuthPlain,
    ChannelCommand,
    Channel9P,
    ChannelSFTP,
    ChannelClipboard,
    ExtensionAllocate,
    StoreCredential,
    Other(Bytes, Option<Bytes>),
}

impl Capability {
    #[allow(clippy::mutable_key_type)]
    pub fn implemented() -> BTreeSet<Capability> {
        [
            Self::AuthExternal,
            Self::AuthKeyboardInteractive,
            Self::AuthPlain,
            Self::ChannelCommand,
            Self::ChannelClipboard,
            Self::Channel9P,
            Self::ChannelSFTP,
            Self::ExtensionAllocate,
            Self::StoreCredential,
        ]
        .iter()
        .cloned()
        .collect()
    }

    pub fn is_implemented(&self) -> bool {
        matches!(
            self,
            Self::AuthExternal
                | Self::AuthKeyboardInteractive
                | Self::AuthPlain
                | Self::ChannelCommand
                | Self::ChannelClipboard
                | Self::Channel9P
                | Self::ChannelSFTP
                | Self::ExtensionAllocate
                | Self::StoreCredential
        )
    }
}

impl From<Capability> for (Bytes, Option<Bytes>) {
    fn from(capa: Capability) -> (Bytes, Option<Bytes>) {
        match capa {
            Capability::AuthExternal => (
                (b"auth" as &[u8]).into(),
                Some((b"EXTERNAL" as &[u8]).into()),
            ),
            Capability::AuthKeyboardInteractive => (
                (b"auth" as &[u8]).into(),
                Some((b"keyboard-interactive" as &[u8]).into()),
            ),
            Capability::AuthPlain => ((b"auth" as &[u8]).into(), Some((b"PLAIN" as &[u8]).into())),
            Capability::ChannelCommand => (
                (b"channel" as &[u8]).into(),
                Some((b"command" as &[u8]).into()),
            ),
            Capability::Channel9P => ((b"channel" as &[u8]).into(), Some((b"9p" as &[u8]).into())),
            Capability::ChannelSFTP => (
                (b"channel" as &[u8]).into(),
                Some((b"sftp" as &[u8]).into()),
            ),
            Capability::ChannelClipboard => (
                (b"channel" as &[u8]).into(),
                Some((b"clipboard" as &[u8]).into()),
            ),
            Capability::StoreCredential => (
                (b"store" as &[u8]).into(),
                Some((b"credential" as &[u8]).into()),
            ),
            Capability::ExtensionAllocate => (
                (b"extension" as &[u8]).into(),
                Some((b"allocate" as &[u8]).into()),
            ),
            Capability::Other(name, subtype) => (name, subtype),
        }
    }
}

impl From<(&[u8], Option<&[u8]>)> for Capability {
    fn from(data: (&[u8], Option<&[u8]>)) -> Capability {
        match data {
            (b"auth", Some(b"EXTERNAL")) => Capability::AuthExternal,
            (b"auth", Some(b"PLAIN")) => Capability::AuthPlain,
            (b"auth", Some(b"keyboard-interactive")) => Capability::AuthKeyboardInteractive,
            (b"channel", Some(b"command")) => Capability::ChannelCommand,
            (b"channel", Some(b"9p")) => Capability::Channel9P,
            (b"channel", Some(b"sftp")) => Capability::ChannelSFTP,
            (b"channel", Some(b"clipboard")) => Capability::ChannelClipboard,
            (b"store", Some(b"credential")) => Capability::StoreCredential,
            (b"extension", Some(b"allocate")) => Capability::ExtensionAllocate,
            (name, subtype) => {
                Capability::Other(name.to_vec().into(), subtype.map(|s| s.to_vec().into()))
            }
        }
    }
}

impl From<(Bytes, Option<Bytes>)> for Capability {
    fn from(data: (Bytes, Option<Bytes>)) -> Capability {
        match data {
            (a, Some(b)) => (&a as &[u8], Some(&b as &[u8])).into(),
            (a, None) => (&a as &[u8], None).into(),
        }
    }
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CapabilityResponse {
    pub version: Vec<u32>,
    pub capabilities: Vec<(Bytes, Option<Bytes>)>,
    pub user_agent: Option<String>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct VersionRequest {
    pub version: u32,
    pub enable: Vec<(Bytes, Option<Bytes>)>,
    pub id: Option<Bytes>,
    pub user_agent: Option<String>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct AuthenticateRequest {
    pub last_id: Option<u32>,
    // All uppercase methods are SASL methods as defined by IANA.  Other methods are defined
    // internally.
    pub method: Bytes,
    pub message: Option<Bytes>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct AuthenticateResponse {
    // All uppercase methods are SASL methods as defined by IANA.  Other methods are defined
    // internally.
    pub method: Bytes,
    pub message: Option<Bytes>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct PartialContinueRequest {
    pub id: u32,
    pub kind: u32,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ContinueRequest<T> {
    pub id: u32,
    pub kind: u32,
    pub message: Option<T>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct AbortRequest {
    pub id: u32,
    pub kind: u32,
}

#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
#[serde(transparent)]
pub struct ChannelID(pub u32);

impl fmt::Display for ChannelID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
#[serde(transparent)]
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
#[serde(rename_all = "kebab-case")]
pub struct CreateChannelRequest {
    pub kind: Bytes,
    pub kind_args: Option<Vec<Bytes>>,
    pub args: Option<Vec<Bytes>>,
    pub env: Option<BTreeMap<Bytes, Bytes>>,
    pub meta: Option<BTreeMap<Bytes, Value>>,
    pub selectors: Vec<u32>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CreateChannelResponse {
    pub id: ChannelID,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DeleteChannelRequest {
    pub id: ChannelID,
    pub termination: Option<u32>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ReadChannelRequest {
    pub id: ChannelID,
    pub selector: u32,
    pub count: u64,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ReadChannelResponse {
    pub bytes: Bytes,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct WriteChannelRequest {
    pub id: ChannelID,
    pub selector: u32,
    pub bytes: Bytes,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct WriteChannelResponse {
    pub count: u64,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
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

#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CreateExtensionRangeRequest {
    pub extension: (Bytes, Option<Bytes>),
    pub count: u32,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CreateExtensionRangeResponse {
    pub range: (u32, u32),
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DeleteExtensionRangeRequest {
    pub extension: (Bytes, Option<Bytes>),
    pub range: (u32, u32),
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ListExtensionRangesResponse {
    pub ranges: Vec<ExtensionRange>,
}

impl IntoIterator for ListExtensionRangesResponse {
    type Item = ExtensionRange;
    type IntoIter = std::vec::IntoIter<ExtensionRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.into_iter()
    }
}

impl<'a> IntoIterator for &'a ListExtensionRangesResponse {
    type Item = &'a ExtensionRange;
    type IntoIter = std::slice::Iter<'a, ExtensionRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter()
    }
}

impl<'a> IntoIterator for &'a mut ListExtensionRangesResponse {
    type Item = &'a mut ExtensionRange;
    type IntoIter = std::slice::IterMut<'a, ExtensionRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter_mut()
    }
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ExtensionRange {
    pub extension: (Bytes, Option<Bytes>),
    pub range: (u32, u32),
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
#[serde(rename_all = "kebab-case")]
pub struct PingChannelRequest {
    pub id: ChannelID,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct PollChannelRequest {
    pub id: ChannelID,
    pub selectors: Vec<u32>,
    pub milliseconds: Option<u32>,
    pub wanted: Option<Vec<u64>>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct PollChannelResponse {
    pub id: ChannelID,
    pub selectors: BTreeMap<u32, u64>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ChannelMetadataNotification {
    pub id: ChannelID,
    pub kind: u32,
    pub status: Option<u32>,
    pub status_kind: Option<u32>,
    pub meta: Option<BTreeMap<Bytes, Value>>,
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub enum ClipboardChannelTarget {
    Primary,
    Clipboard,
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub enum ClipboardChannelOperation {
    Copy,
    Paste,
}

#[derive(Serialize, Deserialize, Hash, Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
#[serde(transparent)]
pub struct StoreID(pub u32);

#[derive(Serialize, Deserialize, Hash, Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
#[serde(transparent)]
pub struct StoreSelectorID(pub u32);

#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum StoreSelector {
    Path(Bytes),
    #[serde(rename = "id")]
    ID(StoreSelectorID),
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct OpenStoreRequest {
    pub kind: Bytes,
    pub path: Option<Bytes>,
    pub meta: Option<BTreeMap<Bytes, Value>>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct OpenStoreResponse {
    pub id: StoreID,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CloseStoreRequest {
    pub id: StoreID,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ListStoreElementsRequest {
    pub id: StoreID,
    pub selector: StoreSelector,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ListStoreElementsResponse {
    pub elements: Vec<StoreElement>,
}

impl IntoIterator for ListStoreElementsResponse {
    type Item = StoreElement;
    type IntoIter = std::vec::IntoIter<StoreElement>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<'a> IntoIterator for &'a ListStoreElementsResponse {
    type Item = &'a StoreElement;
    type IntoIter = std::slice::Iter<'a, StoreElement>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.iter()
    }
}

impl<'a> IntoIterator for &'a mut ListStoreElementsResponse {
    type Item = &'a mut StoreElement;
    type IntoIter = std::slice::IterMut<'a, StoreElement>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.iter_mut()
    }
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct AcquireStoreElementRequest {
    pub id: StoreID,
    pub selector: Bytes,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct AcquireStoreElementResponse {
    pub selector: StoreSelectorID,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CloseStoreElementRequest {
    pub id: StoreID,
    pub selector: StoreSelectorID,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct AuthenticateStoreElementRequest {
    pub id: StoreID,
    pub selector: StoreSelectorID,
    pub method: Bytes,
    pub message: Option<Bytes>,
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct AuthenticateStoreElementResponse {
    pub method: Bytes,
    pub message: Option<Bytes>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct StoreElementBareRequest {
    pub id: StoreID,
    pub selector: StoreSelector,
    pub kind: String,
    pub needs_authentication: Option<bool>,
    pub authentication_methods: Option<Vec<Bytes>>,
    pub meta: Option<BTreeMap<Bytes, Value>>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CreateStoreElementRequest<T> {
    pub id: StoreID,
    pub selector: StoreSelector,
    pub kind: String,
    pub needs_authentication: Option<bool>,
    pub authentication_methods: Option<Vec<Bytes>>,
    pub meta: Option<BTreeMap<Bytes, Value>>,
    pub body: T,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DeleteStoreElementRequest {
    pub id: StoreID,
    pub selector: StoreSelector,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct UpdateStoreElementRequest<T> {
    pub id: StoreID,
    pub selector: StoreSelector,
    pub kind: String,
    pub needs_authentication: Option<bool>,
    pub authentication_methods: Option<Vec<Bytes>>,
    pub meta: Option<BTreeMap<Bytes, Value>>,
    pub body: T,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ReadStoreElementRequest {
    pub id: StoreID,
    pub selector: StoreSelector,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ReadStoreElementResponse<T> {
    pub kind: String,
    pub needs_authentication: Option<bool>,
    pub authentication_methods: Option<Vec<Bytes>>,
    pub meta: Option<BTreeMap<Bytes, Value>>,
    pub body: T,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum StoreSearchRecursionLevel {
    Boolean(bool),
    Levels(u32),
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SearchStoreElementsBareRequest {
    pub id: StoreID,
    pub selector: StoreSelector,
    pub recurse: StoreSearchRecursionLevel,
    pub kind: Option<String>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SearchStoreElementsRequest<T> {
    pub id: StoreID,
    pub selector: StoreSelector,
    pub recurse: StoreSearchRecursionLevel,
    pub kind: Option<String>,
    pub body: Option<T>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SearchStoreElementsResponse<T> {
    pub elements: Vec<StoreElementWithBody<T>>,
}

impl<T> IntoIterator for SearchStoreElementsResponse<T> {
    type Item = StoreElementWithBody<T>;
    type IntoIter = std::vec::IntoIter<StoreElementWithBody<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a SearchStoreElementsResponse<T> {
    type Item = &'a StoreElementWithBody<T>;
    type IntoIter = std::slice::Iter<'a, StoreElementWithBody<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut SearchStoreElementsResponse<T> {
    type Item = &'a mut StoreElementWithBody<T>;
    type IntoIter = std::slice::IterMut<'a, StoreElementWithBody<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.iter_mut()
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct StoreElement {
    pub path: Bytes,
    pub id: Option<StoreSelectorID>,
    pub kind: String,
    pub needs_authentication: Option<bool>,
    pub authentication_methods: Option<Vec<Bytes>>,
    pub meta: Option<BTreeMap<Bytes, Value>>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct StoreElementWithBody<T> {
    pub path: Bytes,
    pub id: Option<StoreSelectorID>,
    pub kind: String,
    pub needs_authentication: Option<bool>,
    pub authentication_methods: Option<Vec<Bytes>>,
    pub meta: Option<BTreeMap<Bytes, Value>>,
    pub body: T,
}

impl<T> StoreElementWithBody<T> {
    pub fn new(elem: StoreElement, body: T) -> Self {
        Self {
            path: elem.path,
            id: elem.id,
            kind: elem.kind,
            needs_authentication: elem.needs_authentication,
            authentication_methods: elem.authentication_methods,
            meta: elem.meta,
            body,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum SearchStoreElementType {
    Literal(Value),
    Set(BTreeSet<SearchStoreElementType>),
    Sequence(Vec<SearchStoreElementType>),
    // The unit value here exists to keep the same form across all serializations.
    Any(()),
    None(()),
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct CredentialStoreSearchElement {
    pub username: SearchStoreElementType,
    pub secret: SearchStoreElementType,
    pub authtype: SearchStoreElementType,
    pub kind: SearchStoreElementType,
    pub protocol: SearchStoreElementType,
    pub host: SearchStoreElementType,
    pub title: SearchStoreElementType,
    pub description: SearchStoreElementType,
    pub path: SearchStoreElementType,
    pub service: SearchStoreElementType,
    pub extra: BTreeMap<String, SearchStoreElementType>,
    pub id: SearchStoreElementType,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CredentialStoreLocation {
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CredentialStoreElement {
    pub username: Option<Bytes>,
    pub secret: Option<Bytes>,
    pub authtype: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub location: Vec<CredentialStoreLocation>,
    pub service: Option<String>,
    pub extra: BTreeMap<String, Value>,
    pub id: Bytes,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct KeyboardInteractiveAuthenticationPrompt {
    pub prompt: String,
    pub echo: bool,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct KeyboardInteractiveAuthenticationRequest {
    pub name: String,
    pub instruction: String,
    pub prompts: Vec<KeyboardInteractiveAuthenticationPrompt>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct KeyboardInteractiveAuthenticationResponse {
    pub responses: Vec<String>,
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

#[derive(Default)]
pub struct ProtocolSerializer {}

pub enum Data {
    Message(Message),
    Response(Response),
}

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum ResponseValue<T: DeserializeOwned, U: DeserializeOwned> {
    Success(T),
    Continuation((u32, U)),
}

impl ProtocolSerializer {
    const MAX_MESSAGE_SIZE: u32 = 0x00ffffff;

    pub fn new() -> ProtocolSerializer {
        Self {}
    }

    pub fn is_valid_size(&self, size: u32) -> bool {
        (8..=Self::MAX_MESSAGE_SIZE).contains(&size)
    }

    pub fn serialize_header(&self, id: u32, next: u32, data_len: usize) -> Option<Bytes> {
        let size = data_len as u64 + 8;
        if size > Self::MAX_MESSAGE_SIZE as u64 {
            return None;
        }
        let mut b = BytesMut::with_capacity(size as usize);
        let size = size as u32;
        b.extend(&size.to_le_bytes());
        b.extend(&id.to_le_bytes());
        b.extend(&next.to_le_bytes());
        Some(b.into())
    }

    pub fn serialize_message_simple(&self, msg: &Message) -> Option<Bytes> {
        let size = 8 + match &msg.message {
            Some(m) => m.len(),
            None => 0,
        };
        if size > Self::MAX_MESSAGE_SIZE as usize {
            return None;
        }
        let mut b = BytesMut::with_capacity(size);
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
        let mut v: Vec<u8> = Vec::with_capacity(12);
        // Write a dummy size that we'll then fill in later.
        v.extend(&0u32.to_le_bytes());
        v.extend(&msg.id.to_le_bytes());
        v.extend(&msg.kind.to_le_bytes());
        let mut cursor = std::io::Cursor::new(&mut v);
        let _ = cursor.seek(SeekFrom::End(0));
        if serde_cbor::to_writer(&mut cursor, obj).is_err() {
            return None;
        }
        let size = match u32::try_from(v.len()) {
            Ok(sz) if (4..=Self::MAX_MESSAGE_SIZE).contains(&sz) => sz - 4,
            _ => return None,
        };
        v[0..4].copy_from_slice(&size.to_le_bytes());
        Some(v.into())
    }

    pub fn serialize_body<S: Serialize>(&self, obj: &S) -> Option<Bytes> {
        match serde_cbor::to_vec(obj) {
            Ok(m) => Some(m.into()),
            Err(_) => None,
        }
    }

    pub fn serialize_response_simple(&self, resp: &Response) -> Option<Bytes> {
        let size = 8 + match &resp.message {
            Some(m) => m.len(),
            None => 0,
        };
        if size > Self::MAX_MESSAGE_SIZE as usize {
            return None;
        }
        let mut b = BytesMut::with_capacity(size);
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
        let mut v: Vec<u8> = Vec::with_capacity(12);
        // Write a dummy size that we'll then fill in later.
        v.extend(&0u32.to_le_bytes());
        v.extend(&msg.id.to_le_bytes());
        v.extend(&msg.code.to_le_bytes());
        let mut cursor = std::io::Cursor::new(&mut v);
        let _ = cursor.seek(SeekFrom::End(0));
        if serde_cbor::to_writer(&mut cursor, obj).is_err() {
            return None;
        }
        let size = match u32::try_from(v.len()) {
            Ok(sz) if (4..=Self::MAX_MESSAGE_SIZE).contains(&sz) => sz - 4,
            _ => return None,
        };
        v[0..4].copy_from_slice(&size.to_le_bytes());
        Some(v.into())
    }

    pub fn deserialize_data(
        &self,
        config: &Config,
        header: &[u8],
        body: Bytes,
    ) -> Result<Data, Error> {
        fn is_sender(config: &Config, id: u32) -> bool {
            let sender_mask = if config.is_server() { 0x80000000 } else { 0 };
            (id & 0x80000000) == sender_mask
        }
        let _size: u32 = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let id: u32 = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let arg: u32 = u32::from_le_bytes(header[8..12].try_into().unwrap());
        if is_sender(config, id) {
            Ok(Data::Response(Response {
                id,
                code: arg,
                message: if body.is_empty() { None } else { Some(body) },
            }))
        } else {
            Ok(Data::Message(Message {
                id,
                kind: arg,
                message: if body.is_empty() { None } else { Some(body) },
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

    pub fn deserialize_response_typed<D1: DeserializeOwned, D2: DeserializeOwned>(
        &self,
        resp: &Response,
    ) -> Result<Option<ResponseValue<D1, D2>>, Error> {
        if resp.code == ResponseCode::Success as u32 {
            match &resp.message {
                Some(body) => match serde_cbor::from_slice(body) {
                    Ok(decoded) => Ok(Some(ResponseValue::Success(decoded))),
                    Err(_) => Err(Error {
                        code: ResponseCode::Invalid,
                        body: None,
                    }),
                },
                None => Ok(None),
            }
        } else if resp.code == ResponseCode::Continuation as u32 {
            match &resp.message {
                Some(body) => match serde_cbor::from_slice(body) {
                    Ok(decoded) => Ok(Some(ResponseValue::Continuation((resp.id, decoded)))),
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

#[cfg(test)]
mod tests {
    use super::{
        ChannelID, Empty, Message, ProtocolSerializer, Response, ResponseValue,
        SearchStoreElementType, StoreID, StoreSelector, StoreSelectorID,
    };
    use bytes::Bytes;
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use serde_cbor::Value;
    use std::convert::TryFrom;
    use std::fmt::Debug;

    #[test]
    fn serialize_header() {
        let cases: &[(u32, u32, usize, Option<&[u8]>)] = &[
            (
                0x01234567,
                0xffeeddcc,
                0x00000000,
                Some(b"\x08\x00\x00\x00\x67\x45\x23\x01\xcc\xdd\xee\xff"),
            ),
            (
                0x87654321,
                0x00000000,
                0x00000099,
                Some(b"\xa1\x00\x00\x00\x21\x43\x65\x87\x00\x00\x00\x00"),
            ),
            (
                0x87654321,
                0x00000000,
                0x00fffff7,
                Some(b"\xff\xff\xff\x00\x21\x43\x65\x87\x00\x00\x00\x00"),
            ),
            (0x87654321, 0x00000000, 0x00fffff8, None),
        ];
        let ser = ProtocolSerializer::new();
        for (id, next, data_len, response) in cases {
            assert_eq!(
                ser.serialize_header(*id, *next, *data_len).as_deref(),
                *response
            );
        }
    }

    fn assert_encode<'a, S: Serialize + Deserialize<'a> + Debug + Clone + PartialEq>(
        desc: &str,
        s: &S,
        seq: &[u8],
    ) {
        let id = 0x01234567u32;
        let next = 0xffeeddccu32;
        let mut header = [0u8; 12];

        header[0..4].copy_from_slice(&u32::try_from(seq.len() + 8).unwrap().to_le_bytes());
        header[4..8].copy_from_slice(&id.to_le_bytes());
        header[8..12].copy_from_slice(&next.to_le_bytes());

        let ser = ProtocolSerializer::new();
        let msg = Message {
            id,
            kind: next,
            message: Some(Bytes::copy_from_slice(seq)),
        };

        let res = ser.serialize_header(id, next, seq.len()).unwrap();
        assert_eq!(&res, &header as &[u8], "header: {}", desc);

        let res = ser.serialize_message_simple(&msg).unwrap();
        assert_eq!(res[0..12], header, "simple header: {}", desc);
        assert_eq!(res[12..], *seq, "simple body: {}", desc);

        let res = ser.serialize_body(s).unwrap();
        assert_eq!(res, *seq, "body: {}", desc);

        let msg = Message {
            id,
            kind: next,
            message: None,
        };
        let res = ser.serialize_message_typed(&msg, s).unwrap();
        assert_eq!(res[0..12], header, "typed header: {}", desc);
        assert_eq!(res[12..], *seq, "typed body: {}", desc);
    }

    fn assert_round_trip<S: Serialize + DeserializeOwned + Debug + Clone + PartialEq>(
        desc: &str,
        s: &S,
        seq: &[u8],
    ) {
        assert_encode(desc, s, seq);
        assert_decode(desc, s, seq);
    }

    fn assert_decode<S: Serialize + DeserializeOwned + Debug + Clone + PartialEq>(
        desc: &str,
        s: &S,
        seq: &[u8],
    ) {
        let id = 0x01234567u32;
        let next = 0u32;
        let mut header = [0u8; 12];

        header[0..4].copy_from_slice(&u32::try_from(seq.len() + 8).unwrap().to_le_bytes());
        header[4..8].copy_from_slice(&id.to_le_bytes());
        header[8..12].copy_from_slice(&next.to_le_bytes());

        let body = Bytes::copy_from_slice(seq);

        let ser = ProtocolSerializer::new();
        let resp = Response {
            id,
            code: next,
            message: Some(body.clone()),
        };

        let mut full_msg: Vec<u8> = header.into();
        full_msg.extend(seq);

        let res = ser.deserialize_response_typed::<S, Empty>(&resp);
        assert_eq!(
            res.unwrap().unwrap(),
            ResponseValue::Success(s.clone()),
            "deserialize typed response: {}",
            desc
        );
    }

    #[test]
    fn serialize_basic_types() {
        assert_round_trip("0u32", &0u32, b"\x00");
        assert_round_trip("all ones u32", &0xfedcba98u32, b"\x1a\xfe\xdc\xba\x98");
        assert_round_trip(
            "simple Bytes",
            &Bytes::from(b"Hello, world!\n" as &'static [u8]),
            b"\x4eHello, world!\n",
        );
        assert_encode("simple &str", &"Hello, world!\n", b"\x6eHello, world!\n");
        assert_round_trip(
            "simple String",
            &String::from("Hello, world!\n"),
            b"\x6eHello, world!\n",
        );
    }

    #[test]
    fn serialize_encoded_types() {
        assert_round_trip("ChannelID 0", &ChannelID(0), b"\x00");
        assert_round_trip(
            "ChannelID all ones u32",
            &ChannelID(0xfedcba98u32),
            b"\x1a\xfe\xdc\xba\x98",
        );
        assert_round_trip("StoreID 0", &StoreID(0), b"\x00");
        assert_round_trip(
            "StoreID pattern",
            &StoreID(0xfedcba98u32),
            b"\x1a\xfe\xdc\xba\x98",
        );
        assert_round_trip("StoreSelectorID 0", &StoreSelectorID(0), b"\x00");
        assert_round_trip(
            "StoreSelectorID pattern",
            &StoreSelectorID(0xfedcba98u32),
            b"\x1a\xfe\xdc\xba\x98",
        );
        assert_round_trip(
            "StoreSelector path",
            &StoreSelector::Path(Bytes::from(b"/dev/null" as &[u8])),
            b"\xa1\x64path\x49/dev/null",
        );
        assert_round_trip(
            "StoreSelector ID",
            &StoreSelector::ID(StoreSelectorID(0xfedcba98u32)),
            b"\xa1\x62id\x1a\xfe\xdc\xba\x98",
        );
        assert_round_trip(
            "SearchStoreElementType literal text",
            &SearchStoreElementType::Literal(Value::Text(String::from("abc123"))),
            b"\xa1\x67literal\x66abc123",
        );
        assert_round_trip(
            "SearchStoreElementType literal bytes",
            &SearchStoreElementType::Literal(Value::Bytes("abc123".into())),
            b"\xa1\x67literal\x46abc123",
        );
        assert_round_trip(
            "SearchStoreElementType literal null",
            &SearchStoreElementType::Literal(Value::Null),
            b"\xa1\x67literal\xf6",
        );
        assert_round_trip(
            "SearchStoreElementType any",
            &SearchStoreElementType::Any(()),
            b"\xa1\x63any\xf6",
        );
        assert_round_trip(
            "SearchStoreElementType none",
            &SearchStoreElementType::None(()),
            b"\xa1\x64none\xf6",
        );
    }

    #[test]
    fn serialize_requests() {
        assert_round_trip(
            "CreateExtensionRangeRequest with no second part",
            &super::CreateExtensionRangeRequest {
                extension: (
                    Bytes::from(b"foobar@test.ns.crustytoothpaste.net" as &[u8]),
                    None,
                ),
                count: 5,
            },
            b"\xa2\x69extension\x82\x58\x23foobar@test.ns.crustytoothpaste.net\xf6\x65count\x05",
        );
        assert_round_trip(
            "CreateExtensionRangeRequest with second part",
            &super::CreateExtensionRangeRequest {
                extension: (
                    Bytes::from(b"foobar@test.ns.crustytoothpaste.net" as &[u8]),
                    Some(Bytes::from(b"v1" as &[u8])),
                ),
                count: 5,
            },
            b"\xa2\x69extension\x82\x58\x23foobar@test.ns.crustytoothpaste.net\x42v1\x65count\x05",
        );
    }

    #[test]
    fn deserialize_requests() {
        assert_decode(
            "CreateExtensionRangeRequest with extension field",
            &super::CreateExtensionRangeRequest {
                extension: (
                    Bytes::from(b"foobar@test.ns.crustytoothpaste.net" as &[u8]),
                    None,
                ),
                count: 5,
            },
            b"\xa3\x69extension\x82\x58\x23foobar@test.ns.crustytoothpaste.net\xf6\x58\x26extension@test.ns.crustytoothpaste.net\xf5\x65count\x05",
        );
    }
}
