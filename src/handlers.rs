use crate::AppState;
use crate::crypto::{validate_ephemeral_pub_key_size, validate_rsa_key_size};
use crate::utils::{add_0x_prefix, strip_0x_prefix};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
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
pub async fn get_public_key(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "publicKey": add_0x_prefix(&state.kms_service.public_key_to_hex()) }))
}

/// Delegate endpoint handler for ECIES shared secret computation.
///
/// This endpoint implements the KMS-side of ECIES (Elliptic Curve Integrated Encryption Scheme)
/// with RSA-wrapped shared secret. It computes the ECDH shared secret from the provided ephemeral
/// public key and the KMS private key, then encrypts the X-coordinate using RSA-OAEP (SHA-256)
/// to delegate the decryption of the shared secret to the owner of the RSA public key.
///
/// # Request Body
///
/// JSON object with the following fields (all hex strings must be 0x-prefixed):
/// - `ephemeralPubKey`: Compressed SEC1 EC public key (33 bytes = 66 hex chars + "0x" prefix)
///   - Format: `0x02...` or `0x03...` followed by 64 hex characters
/// - `targetPubKey`: RSA public key in SPKI DER format (minimum 2048 bits)
///   - Format: `0x` + DER-encoded SubjectPublicKeyInfo
///
/// # Returns
///
/// **Success (200 OK)**:
/// - `encryptedSharedSecret`: 0x-prefixed hex string of the RSA-encrypted shared secret
///   - 512 hex chars for RSA-2048, 1024 hex chars for RSA-4096
///
/// **Error (400 Bad Request)**:
/// - `error`: Description of what went wrong:
///   - Invalid ephemeral public key size (must be 33 bytes)
///   - Invalid RSA key size (must be at least 2048 bits)
///   - Invalid hex encoding
///   - Invalid EC point or RSA key format
///   - RSA encryption failure
pub async fn delegate(
    State(state): State<AppState>,
    Json(payload): Json<DelegateRequest>,
) -> impl IntoResponse {
    let ephemeral_pub_key = strip_0x_prefix(&payload.ephemeral_pub_key);
    let target_pub_key = strip_0x_prefix(&payload.target_pub_key);

    // Validate ephemeral public key size (33 bytes)
    if let Err(e) = validate_ephemeral_pub_key_size(ephemeral_pub_key) {
        return bad_request(e);
    }

    // Validate RSA key size (minimum 2048 bits)
    if let Err(e) = validate_rsa_key_size(target_pub_key) {
        return bad_request(e);
    }

    let result = state
        .kms_service
        .ecies_delegate(ephemeral_pub_key, target_pub_key);
    match result {
        Ok(encrypted_shared_secret_hex) => (
            StatusCode::OK,
            Json(json!({ "encryptedSharedSecret": add_0x_prefix(&encrypted_shared_secret_hex) })),
        )
            .into_response(),
        Err(error) => bad_request(error),
    }
}

pub async fn metrics(State(state): State<AppState>) -> String {
    state.metrics_handle.render()
}

/// Helper to build a BAD_REQUEST response with a JSON error message.
pub fn bad_request(e: impl std::fmt::Display) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": e.to_string() })),
    )
        .into_response()
}
