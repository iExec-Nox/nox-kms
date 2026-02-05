use std::path::PathBuf;

use config::{Config as ConfigBuilder, ConfigError, Environment};
use config_secret::EnvironmentSecretFile;
use serde::Deserialize;
use tracing::debug;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub key_filename: PathBuf,
    pub keystore_filename: PathBuf,
    /// Keystore password (can be set via NOX_KMS_KEYSTORE_PASSWORD or NOX_KMS_KEYSTORE_PASSWORD_FILE)
    pub keystore_password: String,
    pub chain_id: u32,
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
            .set_default("key_filename", "kms.key")?
            .set_default("keystore_filename", "keystore_signer.json")?
            .set_default("keystore_password", "")?
            .set_default("chain_id", 421614)?
            // Load environment variables (NOX_KMS_*)
            .add_source(
                Environment::with_prefix("NOX_KMS")
                    .prefix_separator("_")
                    .separator("__"),
            )
            // Load secrets from files (NOX_KMS_*_FILE -> reads file content)
            .add_source(EnvironmentSecretFile::with_prefix("NOX_KMS").separator("_"))
            .build()?;

        config.try_deserialize()
    }

    pub fn bind_addr(&self) -> String {
        let addr = format!("{}:{}", self.server.host, self.server.port);
        debug!("Starting KMS server on {}", addr);
        addr
    }
}
