use std::collections::HashMap;

use alloy_primitives::{Address, FixedBytes, hex};
use alloy_signer::Signature;
use alloy_sol_types::{SolStruct, eip712_domain, sol};
use axum::{
    Json,
    extract::{Query, State},
    http::{
        StatusCode, Uri,
        header::{AUTHORIZATION, HeaderMap},
    },
    response::IntoResponse,
};
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::warn;

use crate::constants::{EIP_712_DOMAIN_VERSION, PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME};
use crate::crypto::{validate_ephemeral_pub_key_size, validate_rsa_key_size};
use crate::errors::KmsError;
use crate::errors::KmsResult;
use crate::service::KmsService;
use crate::utils::{add_0x_prefix, strip_0x_prefix};

/// Shared query parameters for every versioned endpoint.
///
/// - `salt` — optional 32-byte hex value bound into the Handle Gateway EIP-712
///   response-signing domain so callers can associate a response with a
///   specific request. Absent → `bytes32(0)`.
/// - `chain_id` — only meaningful on `POST /v0/secrets`. Optional; when
///   provided it must equal `config.chain.id`, otherwise the request is
///   rejected (400). When absent the gateway falls back to `config.chain.id`.
///   Other endpoints ignore this field.
#[derive(Debug, Deserialize)]
pub struct QueryParams {
    chain_id: u32,
    salt: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegateRequest {
    pub ephemeral_pub_key: String,
    pub target_pub_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegateResponse {
    pub encrypted_shared_secret: String,
    pub proof: String,
}

sol! {
    #[derive(Debug)]
    struct DelegateAuthorization {
        string ephemeralPubKey;
        string targetPubKey;
    }
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

/// Metrics endpoint handler.
///
/// Returns the Prometheus metrics in the text format.
/// This endpoint is used for monitoring and metrics collection.
pub async fn metrics(State(metrics_handle): State<PrometheusHandle>) -> String {
    metrics_handle.render()
}

/// Fallback handler for non-existing routes.
///
/// Returns 404 NOT_FOUND to indicate the requested route does not exist.
pub async fn not_found(uri: Uri) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error":format!("Route not found {}", uri.path()) })),
    )
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
    State(kms_service): State<KmsService>,
    State(gateway_addresses): State<HashMap<u32, Address>>,
    headers: HeaderMap,
    Query(query_params): Query<QueryParams>,
    Json(payload): Json<DelegateRequest>,
) -> KmsResult<Json<DelegateResponse>> {
    let chain_id = query_params.chain_id;
    if !gateway_addresses.contains_key(&chain_id) {
        warn!("Unknown Chain ID {chain_id}");
        return Err(KmsError::InvalidQueryParams(format!(
            "Unknown Chain ID {chain_id}"
        )));
    }

    let bytes = hex::decode(&query_params.salt)
        .inspect_err(|e| warn!("Salt {} is not a valid hex: {e}", query_params.salt))
        .map_err(|e| KmsError::InvalidQueryParams(format!("{e}")))?;
    if bytes.len() != 32 {
        warn!("Salt {} length must be 32-bytes", query_params.salt);
        return Err(KmsError::InvalidQueryParams(
            "Salt length must be 32 bytes".to_string(),
        ));
    }
    let salt = FixedBytes::<32>::from_slice(&bytes);

    let signature_str = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| KmsError::Unauthorized("Authorization header is required".to_string()))?
        .to_str()
        .map_err(|e| KmsError::Unauthorized(format!("Invalid Authorization header: {}", e)))?
        .strip_prefix("Bearer 0x")
        .ok_or_else(|| {
            KmsError::Unauthorized(
                "Expected format of authorization header: 'Bearer 0x<signature>'".to_string(),
            )
        })?;

    verify_delegate_authorization(
        signature_str,
        chain_id,
        &payload,
        gateway_addresses[&chain_id],
    )?;

    let ephemeral_pub_key = strip_0x_prefix(&payload.ephemeral_pub_key);
    let target_pub_key = strip_0x_prefix(&payload.target_pub_key);

    // Validate ephemeral public key size (33 bytes)
    validate_ephemeral_pub_key_size(ephemeral_pub_key)?;

    // Validate RSA key size (minimum 2048 bits)
    validate_rsa_key_size(target_pub_key)?;

    let encrypted_shared_secret_hex =
        kms_service.ecies_delegate(chain_id, ephemeral_pub_key, target_pub_key)?;
    let prefixed_encrypted_shared_secret = add_0x_prefix(&encrypted_shared_secret_hex);
    Ok(Json(DelegateResponse {
        encrypted_shared_secret: prefixed_encrypted_shared_secret.clone(),
        proof: kms_service.compute_delegate_response_proof(
            chain_id,
            salt,
            &prefixed_encrypted_shared_secret,
        )?,
    }))
}

/// Verifies the EIP-712 signature for a delegate authorization request.
///
/// # Arguments
///
/// * `signature_str` - The hex-encoded signature (without 0x prefix)
/// * `chain_id` - The chain ID for the EIP-712 domain
/// * `payload` - The delegate request containing the data that was signed
///
/// # Returns
///
/// () on success, or a `KmsError` on failure.
fn verify_delegate_authorization(
    signature_str: &str,
    chain_id: u32,
    payload: &DelegateRequest,
    gateway_address: Address,
) -> KmsResult<()> {
    let domain = eip712_domain! {
        name: PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME,
        version: EIP_712_DOMAIN_VERSION,
        chain_id: u64::from(chain_id),
    };

    let signature_bytes =
        hex::decode(signature_str).map_err(|e| KmsError::Unauthorized(e.to_string()))?;

    let signature =
        Signature::from_raw(&signature_bytes).map_err(|e| KmsError::Unauthorized(e.to_string()))?;

    let authorization = DelegateAuthorization {
        ephemeralPubKey: payload.ephemeral_pub_key.clone(),
        targetPubKey: payload.target_pub_key.clone(),
    };

    let hash = authorization.eip712_signing_hash(&domain);
    let recovered = signature
        .recover_address_from_prehash(&hash)
        .map_err(|e| KmsError::Unauthorized(e.to_string()))?;

    if recovered != gateway_address {
        return Err(KmsError::Unauthorized(format!(
            "signer {recovered} does not match gateway {gateway_address}"
        )));
    }

    Ok(())
}
