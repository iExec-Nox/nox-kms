use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;
use thiserror::Error;
use tracing::warn;

#[derive(Error, Debug)]
pub enum KmsError {
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Authentication error: {0}")]
    Authentication(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

impl IntoResponse for KmsError {
    fn into_response(self) -> axum::response::Response {
        warn!("Request failed: {}", self);
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

pub type KmsResult<T> = Result<T, KmsError>;
