use alloy_primitives::Address;
use config::{Config as ConfigBuilder, ConfigError, Environment};
use config_secret::EnvironmentSecretFile;
use serde::Deserialize;
use tracing::debug;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub chain: ChainConfig,
    pub server: ServerConfig,
    pub ecc_key: String,
    pub wallet_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    pub chain_id: u32,
    pub nox_compute_contract: Address,
    pub rpc_url: String,
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        let config = ConfigBuilder::builder()
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 9000)?
            .set_default("ecc_key", "")?
            .set_default("wallet_key", "")?
            .set_default("chain.chain_id", 421614)?
            .set_default(
                "chain.nox_compute_contract",
                "0x0000000000000000000000000000000000000000",
            )?
            .set_default("chain.rpc_url", "http://localhost:8545")?
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
