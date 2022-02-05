use std::sync::Arc;
use std::time::Duration;

pub struct Config {
    server: bool,
    logger: Arc<dyn Logger + Send + Sync>,
    max_messages_in_flight: u32,
    closing_delay: Duration,
}

impl Config {
    const ID_MASK: u32 = 0x7fffffff;

    pub fn new(server: bool, logger: Arc<dyn Logger + Send + Sync>) -> Self {
        Self {
            server,
            logger,
            max_messages_in_flight: 1024,
            closing_delay: Duration::from_millis(1000),
        }
    }

    /// Returns the next valid ID based on the current ID and the configuration.
    pub(crate) fn first_id(&self) -> u32 {
        if self.server {
            0x80000000
        } else {
            0
        }
    }

    /// Returns the next valid ID based on the current ID and the configuration.
    pub(crate) fn next_id(&self, id: u32) -> u32 {
        let top_bit = if self.server { 0x80000000 } else { 0 };
        ((id.wrapping_add(1)) & Self::ID_MASK) | top_bit
    }

    pub fn is_server(&self) -> bool {
        self.server
    }

    pub fn max_messages_in_flight(&self) -> u32 {
        self.max_messages_in_flight
    }

    pub fn closing_delay(&self) -> Duration {
        self.closing_delay
    }

    pub fn logger(&self) -> Arc<dyn Logger + Send + Sync> {
        self.logger.clone()
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum LogLevel {
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
