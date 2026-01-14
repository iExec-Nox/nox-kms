use thiserror::Error;

#[derive(Error, Debug)]
pub enum KmsError {
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    #[error("Storage error: {0}")]
    Storage(String),
}

pub type KmsResult<T> = Result<T, KmsError>;
