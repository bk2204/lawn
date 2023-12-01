use crate::fs_proxy;
use lawn_protocol::{handler, protocol};
use std::borrow::{Borrow, Cow};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::fmt::{Debug, Display};
use std::io;

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

impl From<crate::credential::CredentialError> for Error {
    fn from(err: crate::credential::CredentialError) -> Error {
        type E = crate::credential::CredentialError;
        match err {
            E::EmptyResponse(_) => {
                let s = err.to_string();
                Error::new_full(ErrorKind::MissingResponse, err, s)
            }
            E::ProtocolFailure(e) => e,
            E::Conflict | E::NotFound | E::UnsupportedSerialization => {
                let s = err.to_string();
                Error::new_full(ErrorKind::CredentialError, err, s)
            }
        }
    }
}

/// A trait to allow logging and scripting of error values.
pub trait ExtendedError {
    /// The types of errors.
    ///
    /// This provides a list of string error types that classify this error.  For example, a
    /// credential error that wraps an I/O error might indicate `["credential-error", "io-error"].
    fn error_types(&self) -> Cow<'static, [Cow<'static, str>]>;
    /// The tag of an error.
    ///
    /// This tag represents the error as a simple dash-divided string that indicates this specific
    /// error.  This will usually be a kebab-case version of the error kind.
    fn error_tag(&self) -> Cow<'static, str>;
}

#[derive(Debug)]
pub struct WrongTypeError<T>(pub T);

#[derive(Debug)]
pub struct MissingElementError<T>(Cow<'static, str>, T);

impl<T> Display for MissingElementError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "missing element {}", self.0)
    }
}

impl<T> MissingElementError<T> {
    pub fn new<S: Into<Cow<'static, str>>>(name: S, element: T) -> Self {
        MissingElementError(name.into(), element)
    }

    pub fn element_name(&self) -> &str {
        self.0.borrow()
    }

    pub fn into_inner(self) -> T {
        self.1
    }
}

impl<T: Debug> std::error::Error for MissingElementError<T> {}

impl TryFrom<Error> for handler::Error {
    type Error = WrongTypeError<Error>;
    fn try_from(e: Error) -> Result<handler::Error, Self::Error> {
        match e.kind {
            ErrorKind::HandlerError => match e.cause {
                Some(mut cause) => match cause.downcast_mut::<handler::Error>() {
                    Some(e) => Ok(std::mem::replace(e, handler::Error::Unserializable)),
                    None => Err(WrongTypeError(Error {
                        kind: e.kind,
                        cause: Some(cause),
                        message: e.message,
                    })),
                },
                None => Err(WrongTypeError(e)),
            },
            _ => Err(WrongTypeError(e)),
        }
    }
}

impl TryFrom<Error> for protocol::Error {
    type Error = WrongTypeError<Error>;
    fn try_from(e: Error) -> Result<protocol::Error, Self::Error> {
        let err = handler::Error::try_from(e)?;
        if let handler::Error::ProtocolError(e) = err {
            return Ok(e);
        }
        Err(WrongTypeError(err.into()))
    }
}

impl TryFrom<Error> for io::Error {
    type Error = WrongTypeError<Error>;
    fn try_from(e: Error) -> Result<io::Error, Self::Error> {
        let err = protocol::Error::try_from(e)?;
        let e: Result<io::Error, _> = err.try_into();
        e.map_err(|e| WrongTypeError(handler::Error::from(e.0).into()))
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
    CredentialError,
}

impl From<ErrorKind> for i32 {
    fn from(_e: ErrorKind) -> i32 {
        2
    }
}
