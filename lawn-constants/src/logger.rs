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
