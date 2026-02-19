use alloy_primitives::Address;
use alloy_signer::Signature;
use alloy_sol_types::{SolStruct, eip712_domain, sol};
use axum::{
    Json,
    extract::State,
    http::header::{AUTHORIZATION, HeaderMap},
};
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::constants::{EIP_712_DOMAIN_VERSION, PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME};
use crate::crypto::{validate_ephemeral_pub_key_size, validate_rsa_key_size};
use crate::errors::KmsError;
use crate::errors::KmsResult;
use crate::service::KmsService;
use crate::utils::{add_0x_prefix, strip_0x_prefix};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegateRequest {
    pub ephemeral_pub_key: String,
    pub target_pub_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyResponse {
    pub public_key: String,
    pub proof: String,
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
    State(gateway_address): State<Address>,
    headers: HeaderMap,
    Json(payload): Json<DelegateRequest>,
) -> KmsResult<Json<DelegateResponse>> {
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
        u64::from(kms_service.chain_id),
        &payload,
        gateway_address,
    )?;

    let ephemeral_pub_key = strip_0x_prefix(&payload.ephemeral_pub_key);
    let target_pub_key = strip_0x_prefix(&payload.target_pub_key);

    // Validate ephemeral public key size (33 bytes)
    validate_ephemeral_pub_key_size(ephemeral_pub_key)?;

    // Validate RSA key size (minimum 2048 bits)
    validate_rsa_key_size(target_pub_key)?;

    let encrypted_shared_secret_hex =
        kms_service.ecies_delegate(ephemeral_pub_key, target_pub_key)?;
    Ok(Json(DelegateResponse {
        encrypted_shared_secret: add_0x_prefix(&encrypted_shared_secret_hex),
        proof: kms_service.compute_delegate_response_proof(&encrypted_shared_secret_hex)?,
    }))
}

pub async fn metrics(State(metrics_handle): State<PrometheusHandle>) -> String {
    metrics_handle.render()
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
    chain_id: u64,
    payload: &DelegateRequest,
    gateway_address: Address,
) -> KmsResult<()> {
    let domain = eip712_domain! {
        name: PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME,
        version: EIP_712_DOMAIN_VERSION,
        chain_id: chain_id,
    };

    let signature_bytes =
        hex::decode(signature_str).map_err(|e| KmsError::Unauthorized(e.to_string()))?;

    let signature =
        Signature::from_raw(&signature_bytes).map_err(|e| KmsError::Unauthorized(e.to_string()))?;

    let authorization = DelegateAuthorization {
        ephemeralPubKey: strip_0x_prefix(&payload.ephemeral_pub_key).to_string(),
        targetPubKey: strip_0x_prefix(&payload.target_pub_key).to_string(),
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
