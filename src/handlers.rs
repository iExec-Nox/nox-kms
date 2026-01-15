use crate::service::KmsService;
use crate::utils::{add_0x_prefix, strip_0x_prefix};
use axum::{Json, extract::State, response::IntoResponse};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegateRequest {
    pub ephemeral_pub_key: String,
    pub target_pub_key: String,
}

/// Root endpoint handler.
///
/// Returns basic service information including the service name and current timestamp.
/// This endpoint is typically used for service discovery and basic connectivity checks.
///
/// # Returns
///
/// JSON response containing:
/// - `service`: The service name ("nox-kms")
/// - `timestamp`: Current UTC timestamp in RFC3339 format
pub async fn root() -> Json<Value> {
    Json(json!({
        "service": "nox-kms",
        "timestamp": Utc::now().to_rfc3339()
    }))
}

/// Health check endpoint handler.
///
/// Returns a simple "OK" response to indicate that the service is running.
/// This endpoint is typically used for health checks and service monitoring.
///
/// # Returns
///
/// JSON response containing:
/// - `status`: The status of the service ("ok")
pub async fn health_check() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// Get public key endpoint handler.
///
/// Returns the public key of the KMS service.
///
/// # Returns
///
/// JSON response containing:
/// - `public_key`: The public key of the KMS service
pub async fn get_public_key(State(kms_service): State<KmsService>) -> Json<Value> {
    Json(json!({ "publicKey": kms_service.public_key_to_hex() }))
}

/// Delegate the computation of the encrypted shared secret RSA(K*priv_key).
/// Inputs and output are 0x-prefixed hex strings.
pub async fn delegate(
    State(kms_service): State<KmsService>,
    Json(payload): Json<DelegateRequest>,
) -> impl IntoResponse {
    let ephemeral_pub_key = strip_0x_prefix(&payload.ephemeral_pub_key);
    let target_pub_key = strip_0x_prefix(&payload.target_pub_key);

    let result = kms_service.ecies_delegate(ephemeral_pub_key, target_pub_key);
    match result {
        Ok(encrypted_shared_secret_hex) => (
            axum::http::StatusCode::OK,
            Json(json!({ "encryptedSharedSecret": add_0x_prefix(&encrypted_shared_secret_hex) })),
        )
            .into_response(),
        Err(error) => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}
