use std::fmt;
use std::sync::Arc;

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum LogLevel {
    Dump,
    Trace,
    Debug,
    Info,
    Normal,
    Error,
    Fatal,
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub enum LogFormat {
    CBOR,
    JSON,
    Text,
    Scriptable,
}

pub trait Logger {
    fn level(&self) -> LogLevel;
    fn format(&self) -> LogFormat;
    fn fatal(&self, msg: &str);
    fn error(&self, msg: &str);
    fn message(&self, msg: &str);
    fn info(&self, msg: &str);
    fn debug(&self, msg: &str);
    fn trace(&self, msg: &str);
}

impl<T: Logger> Logger for Arc<T> {
    fn level(&self) -> LogLevel {
        self.as_ref().level()
    }

    fn format(&self) -> LogFormat {
        self.as_ref().format()
    }

    fn fatal(&self, msg: &str) {
        self.as_ref().fatal(msg);
    }

    fn error(&self, msg: &str) {
        self.as_ref().error(msg);
    }

    fn message(&self, msg: &str) {
        self.as_ref().message(msg);
    }

    fn info(&self, msg: &str) {
        self.as_ref().info(msg);
    }

    fn debug(&self, msg: &str) {
        self.as_ref().debug(msg);
    }

    fn trace(&self, msg: &str) {
        self.as_ref().trace(msg);
    }
}

pub trait AsLogStr<'a> {
    fn as_log_str(&'a self) -> LogStr<'a>;
}

impl<'a> AsLogStr<'a> for &'a [u8] {
    fn as_log_str(&'a self) -> LogStr<'a> {
        LogStr::Bytes(self)
    }
}

pub trait AsHexLogStr<'a> {
    fn as_hex_log_str(&'a self) -> HexLogStr<'a>;
}

impl<'a> AsHexLogStr<'a> for &'a [u8] {
    fn as_hex_log_str(&'a self) -> HexLogStr<'a> {
        HexLogStr::Bytes(self)
    }
}

pub enum LogStr<'a> {
    Bytes(&'a [u8]),
}

impl<'a> fmt::Display for LogStr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        use std::fmt::Write;
        match self {
            Self::Bytes(arr) => {
                for c in arr
                    .iter()
                    .flat_map(|c| std::ascii::escape_default(*c))
                    .map(|c| c as char)
                {
                    f.write_char(c)?
                }
            }
        }
        Ok(())
    }
}

impl<'a> fmt::Debug for LogStr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Display::fmt(self, f)
    }
}

pub enum HexLogStr<'a> {
    Bytes(&'a [u8]),
}

impl<'a> fmt::Display for HexLogStr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Bytes(arr) => {
                for b in *arr {
                    write!(f, "{:02x}", b)?;
                }
            }
        }
        Ok(())
    }
}

impl<'a> fmt::Debug for HexLogStr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Display::fmt(self, f)
    }
}

#[macro_export]
macro_rules! trace {
    ($logger:expr, $($args : tt) *) => {
        {
            use lawn_constants::logger::{Logger, LogLevel};
            if $logger.level() >= LogLevel::Trace {
                $logger.trace(&format!($($args)*));
            }
        }
    }
}

#[macro_export]
macro_rules! debug {
    ($logger:expr, $($args : tt) *) => {
        {
            use lawn_constants::logger::{Logger, LogLevel};
            if $logger.level() >= LogLevel::Debug {
                $logger.debug(&format!($($args)*));
            }
        }
    }
}

#[macro_export]
macro_rules! error {
    ($logger:expr, $($args : tt) *) => {
        {
            use lawn_constants::logger::{Logger, LogLevel};
            if $logger.level() >= LogLevel::Error {
                $logger.error(&format!($($args)*));
            }
        }
    }
}

#[macro_export]
macro_rules! info {
    ($logger:expr, $($args : tt) *) => {
        {
            use lawn_constants::logger::{Logger, LogLevel};
            if $logger.level() >= LogLevel::Info {
                $logger.info(&format!($($args)*));
            }
        }
    }
}

#[macro_export]
macro_rules! message {
    ($logger:expr, $($args : tt) *) => {
        {
            use lawn_constants::logger::{Logger, LogLevel};
            if $logger.level() >= LogLevel::Normal {
                $logger.message(&format!($($args)*));
            }
        }
    }
}
