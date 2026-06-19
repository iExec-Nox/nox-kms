use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

use alloy::primitives::{Address, hex};
use config::{Config as ConfigBuilder, ConfigError, Environment};
use config_secret::EnvironmentSecretFile;
use serde::Deserialize;
use tracing::debug;
use validator::{Validate, ValidationError};

#[derive(Debug, Deserialize, Validate)]
pub struct Config {
    #[validate(nested)]
    pub chains: HashMap<u32, ChainConfig>,
    #[validate(nested)]
    pub server: ServerConfig,
    #[validate(custom(function = "validate_wallet_key"))]
    pub wallet_key: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ChainConfig {
    #[serde(with = "humantime_serde", default = "default_rpc_call_timeout")]
    #[validate(custom(function = "validate_timeout"))]
    pub call_timeout: Duration,
    #[serde(with = "humantime_serde", default = "default_rpc_connect_timeout")]
    #[validate(custom(function = "validate_timeout"))]
    pub connect_timeout: Duration,
    #[validate(custom(function = "validate_ecc_key"))]
    pub ecc_key: String,
    #[validate(custom(function = "validate_nox_compute_contract_address"))]
    pub nox_compute_contract_address: Address,
    #[validate(url)]
    pub rpc_url: String,
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        let config = ConfigBuilder::builder()
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 9000)?
            .set_default("wallet_key", "")?
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

fn default_rpc_call_timeout() -> Duration {
    Duration::from_secs(8)
}

fn default_rpc_connect_timeout() -> Duration {
    Duration::from_secs(5)
}

fn validate_ecc_key(ecc_key: &str) -> Result<(), ValidationError> {
    let ecc_key_bytes =
        hex::decode(ecc_key).map_err(|_| ValidationError::new("ECC key is not a valid hex"))?;
    if ecc_key_bytes.len() != 32 {
        return Err(ValidationError::new("ECC key should have a 32-byte length"));
    }
    if ecc_key_bytes == [0u8; 32] {
        return Err(ValidationError::new("ECC key should not contain only 0"));
    }
    Ok(())
}

fn validate_nox_compute_contract_address(
    nox_compute_contract_address: &Address,
) -> Result<(), ValidationError> {
    if *nox_compute_contract_address == Address::ZERO {
        return Err(ValidationError::new(
            "NoxCompute contract address should not be zero address",
        ));
    }
    Ok(())
}

/// Validate a timeout is not zero and is less than 60 seconds.
fn validate_timeout(value: &Duration) -> Result<(), ValidationError> {
    if *value == Duration::ZERO {
        let err =
            ValidationError::new("timeout_zero").with_message(Cow::from("must be greater than 0s"));
        return Err(err);
    }
    if *value > Duration::from_secs(60) {
        let err = ValidationError::new("timeout_too_large")
            .with_message(Cow::from("must not exceed 60s"));
        return Err(err);
    }
    Ok(())
}

fn validate_wallet_key(wallet_key: &str) -> Result<(), ValidationError> {
    let wallet_key_bytes = hex::decode(wallet_key)
        .map_err(|_| ValidationError::new("wallet key is not a valid hex"))?;
    if wallet_key_bytes.len() != 32 {
        return Err(ValidationError::new(
            "wallet key should have a 32-byte length",
        ));
    }
    if wallet_key_bytes == [0u8; 32] {
        return Err(ValidationError::new("wallet key should not contain only 0"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use validator::ValidationErrors;

    #[test]
    fn check_config() {
        temp_env::with_vars(
            [
                ("NOX_KMS_CHAINS__31337__CALL_TIMEOUT", Some("10s")),
                ("NOX_KMS_CHAINS__31337__CONNECT_TIMEOUT", Some("5s")),
                (
                    "NOX_KMS_CHAINS__31337__ECC_KEY",
                    Some("0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"),
                ),
                (
                    "NOX_KMS_CHAINS__31337__NOX_COMPUTE_CONTRACT_ADDRESS",
                    Some("0x4bf1831c7060E01753863394820B0B940660f4C7"),
                ),
                (
                    "NOX_KMS_CHAINS__31337__RPC_URL",
                    Some("http://localhost:8545"),
                ),
                (
                    "NOX_KMS_WALLET_KEY",
                    Some("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                ),
            ],
            || {
                let config = Config::load().expect("should load");
                config.validate().expect("should validate");
                assert_eq!(
                    Duration::from_secs(5),
                    config.chains[&31337].connect_timeout
                );
                assert_eq!(Duration::from_secs(10), config.chains[&31337].call_timeout);
                assert_eq!(
                    "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                    config.chains[&31337].ecc_key
                );
                assert_eq!(
                    Address::from_str("0x4bf1831c7060E01753863394820B0B940660f4C7").unwrap(),
                    config.chains[&31337].nox_compute_contract_address
                );
                assert_eq!("http://localhost:8545", config.chains[&31337].rpc_url);
                assert_eq!(
                    "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    config.wallet_key
                );
            },
        )
    }

    #[test]
    fn check_invalid_config() {
        temp_env::with_vars(
            [
                ("NOX_KMS_CHAINS__31337__RPC_URL", Some("")),
                (
                    "NOX_KMS_CHAINS__31337__NOX_COMPUTE_CONTRACT_ADDRESS",
                    Some("0x0000000000000000000000000000000000000000"),
                ),
                (
                    "NOX_KMS_CHAINS__31337__ECC_KEY",
                    Some("0x0000000000000000000000000000000000000000000000000000000000000000"),
                ),
            ],
            || {
                let config = Config::load().expect("should load");
                let result = config.validate();
                assert!(result.is_err());
                assert!(ValidationErrors::has_error(&result, "chains"));
                assert!(ValidationErrors::has_error(&result, "wallet_key"));
            },
        )
    }

    #[test]
    fn check_invalid_chain_config() {
        let chain_config = ChainConfig {
            call_timeout: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(90),
            ecc_key: "".to_string(),
            nox_compute_contract_address: Address::ZERO,
            rpc_url: "".to_string(),
        };
        let result = chain_config.validate();
        assert!(ValidationErrors::has_error(&result, "call_timeout"));
        assert!(ValidationErrors::has_error(&result, "connect_timeout"));
        assert!(ValidationErrors::has_error(&result, "ecc_key"));
        assert!(ValidationErrors::has_error(
            &result,
            "nox_compute_contract_address"
        ));
        assert!(ValidationErrors::has_error(&result, "rpc_url"));
    }
}
