use crate::fs_proxy;
use lawn_protocol::{handler, protocol};
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Display;

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: Option<String>,
    cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            message: None,
            cause: None,
        }
    }

    pub fn new_with_message<M: Into<String>>(kind: ErrorKind, message: M) -> Self {
        Self {
            kind,
            message: Some(message.into()),
            cause: None,
        }
    }

    pub fn new_with_cause<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
        kind: ErrorKind,
        cause: E,
    ) -> Self {
        Self {
            kind,
            message: None,
            cause: Some(cause.into()),
        }
    }

    pub fn new_full<M: Into<String>, E: Into<Box<dyn std::error::Error + Send + Sync>>>(
        kind: ErrorKind,
        cause: E,
        message: M,
    ) -> Self {
        Self {
            kind,
            message: Some(message.into()),
            cause: Some(cause.into()),
        }
    }
}

// TODO: fix
impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let handled = match self.kind {
            ErrorKind::NotRootMachine => {
                write!(
                    f,
                    "no server found and autospawn is disabled because we are not the root machine"
                )?;
                true
            }
            _ => false,
        };
        match (handled, &self.message) {
            (true, Some(msg)) => write!(f, "{}", msg)?,
            (false, Some(msg)) => write!(f, "{:?}: {}", self.kind, msg)?,
            (true, None) => (),
            (false, None) => write!(f, "{:?}", self.kind)?,
        };
        if let Some(e) = &self.cause {
            write!(f, ": {}", e)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Some(e) => Some(e.as_ref()),
            None => None,
        }
    }
}

impl From<fs_proxy::Error> for Error {
    fn from(err: fs_proxy::Error) -> Error {
        match err {
            fs_proxy::Error::IOError(e) => Error::new_with_cause(ErrorKind::FSProxyError, e),
            fs_proxy::Error::LawnError(e) => e,
        }
    }
}

impl From<handler::Error> for Error {
    fn from(err: handler::Error) -> Error {
        Error {
            kind: ErrorKind::HandlerError,
            message: None,
            cause: Some(err.into()),
        }
    }
}

impl From<Error> for i32 {
    fn from(e: Error) -> i32 {
        e.kind.into()
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct WrongTypeError;

impl TryFrom<Error> for handler::Error {
    type Error = WrongTypeError;
    fn try_from(e: Error) -> Result<handler::Error, Self::Error> {
        match e.kind {
            ErrorKind::HandlerError => match e.cause {
                Some(mut cause) => match cause.downcast_mut::<handler::Error>() {
                    Some(e) => Ok(std::mem::replace(e, handler::Error::Unserializable)),
                    None => Err(WrongTypeError),
                },
                None => Err(WrongTypeError),
            },
            _ => Err(WrongTypeError),
        }
    }
}

impl TryFrom<Error> for protocol::Error {
    type Error = WrongTypeError;
    fn try_from(e: Error) -> Result<protocol::Error, Self::Error> {
        let err = handler::Error::try_from(e)?;
        if let handler::Error::ProtocolError(e) = err {
            return Ok(e);
        }
        Err(WrongTypeError)
    }
}

#[derive(Debug, Clone)]
pub enum ErrorKind {
    Unimplemented,
    ServerCreationFailure,
    SocketConnectionFailure,
    SocketBindFailure,
    NoSuchSocket,
    RuntimeDirectoryFailure,
    NotConnected,
    HandlerError,
    InvalidConfigFile,
    MissingConfigFile,
    MissingRequiredConfigOption,
    MissingResponse,
    UnexpectedContinuation,
    CommandFailure,
    TemplateError,
    UnknownCommandType,
    UnknownProtocolType,
    MissingArguments,
    IncompatibleArguments,
    NotRootMachine,
    InvalidConfigurationValue,
    ConfigurationSpawnError,
    FSProxyError,
}

impl From<ErrorKind> for i32 {
    fn from(_e: ErrorKind) -> i32 {
        2
    }
}
