use crate::p9p_proxy;
use lawn_protocol::handler;
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

impl From<p9p_proxy::Error> for Error {
    fn from(err: p9p_proxy::Error) -> Error {
        match err {
            p9p_proxy::Error::IOError(e) => Error::new_with_cause(ErrorKind::P9PProxyError, e),
            p9p_proxy::Error::LawnError(e) => e,
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
    CommandFailure,
    TemplateError,
    UnknownCommandType,
    MissingArguments,
    IncompatibleArguments,
    NotRootMachine,
    InvalidConfigurationValue,
    ConfigurationSpawnError,
    P9PProxyError,
}

impl From<ErrorKind> for i32 {
    fn from(_e: ErrorKind) -> i32 {
        2
    }
}
