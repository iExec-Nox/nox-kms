use std::path::PathBuf;

use config::{Config as ConfigBuilder, ConfigError, Environment};
use serde::Deserialize;
use tracing::debug;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        let config = ConfigBuilder::builder()
            .set_default("server.host", "0.0.0.0")?
            .set_default("server.port", 9000)?
            .set_default("key_file", "kms.key")?
            .add_source(
                Environment::with_prefix("NOX_KMS")
                    .prefix_separator("_")
                    .separator("__"),
            )
            .build()?;

        config.try_deserialize()
    }

    pub fn bind_addr(&self) -> String {
        let addr = format!("{}:{}", self.server.host, self.server.port);
        debug!("Starting KMS server on {}", addr);
        addr
    }
}
