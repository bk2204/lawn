pub use lawn_constants::logger::{LogFormat, LogLevel, Logger};
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
