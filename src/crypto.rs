use alloy_primitives::hex;
use alloy_signer_local::PrivateKeySigner;
use k256::{
    FieldBytes, ProjectivePoint, Scalar as F,
    elliptic_curve::{PrimeField, rand_core::OsRng, sec1::FromEncodedPoint},
};
use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey};
use sha2::Sha256;

use crate::constants::{
    EXPECTED_EPHEMERAL_PUB_KEY_HEX_LEN, G, MIN_RSA_KEY_HEX_LEN, SECP256K1_PRIVATE_KEY_SIZE,
};
use crate::errors::{KmsError, KmsResult};

/// Imports an EC key pair from a hex-encoded private key (with 0x prefix).
///
/// Returns the private and public key, just like generate_ec_key_pair().
pub fn import_ec_key_pair(hex_key: &str) -> KmsResult<(F, ProjectivePoint)> {
    // Remove 0x prefix if present
    let hex_clean = hex_key.strip_prefix("0x").unwrap_or(hex_key);

    // Decode hex to bytes (should be SECP256K1_PRIVATE_KEY_SIZE bytes = 64 hex chars)
    let bytes = hex::decode(hex_clean)
        .map_err(|e| KmsError::Crypto(format!("Invalid hex string in NOX_KMS_ECC_KEY: {}", e)))?;

    if bytes.len() != SECP256K1_PRIVATE_KEY_SIZE {
        return Err(KmsError::Crypto(format!(
            "Invalid private key size in NOX_KMS_ECC_KEY: expected {} bytes (64 hex chars), got {} bytes",
            SECP256K1_PRIVATE_KEY_SIZE,
            bytes.len()
        )));
    }

    // Convert bytes to Scalar using from_repr which validates the scalar is in valid range
    let mut bytes_array = [0u8; SECP256K1_PRIVATE_KEY_SIZE];
    bytes_array.copy_from_slice(&bytes);
    let field_bytes = FieldBytes::from(bytes_array);
    let private_key = F::from_repr(field_bytes).into_option().ok_or_else(|| {
        KmsError::Crypto(
            "Invalid private key in NOX_KMS_ECC_KEY: value must be less than curve order"
                .to_string(),
        )
    })?;

    // Compute public key from private key
    let public_key = G * private_key;

    Ok((private_key, public_key))
}

/// Imports a wallet signing key from a hex-encoded private key (with 0x prefix).
///
/// Returns the PrivateKeySigner, just like generate_sign_key().
pub fn import_wallet_key(hex_key: &str) -> KmsResult<PrivateKeySigner> {
    // Remove 0x prefix if present
    let hex_clean = hex_key.strip_prefix("0x").unwrap_or(hex_key);

    // Decode hex to bytes (should be SECP256K1_PRIVATE_KEY_SIZE bytes = 64 hex chars)
    let bytes = hex::decode(hex_clean).map_err(|e| {
        KmsError::Crypto(format!("Invalid hex string in NOX_KMS_WALLET_KEY: {}", e))
    })?;

    if bytes.len() != SECP256K1_PRIVATE_KEY_SIZE {
        return Err(KmsError::Crypto(format!(
            "Invalid private key size in NOX_KMS_WALLET_KEY: expected {} bytes (64 hex chars), got {} bytes",
            SECP256K1_PRIVATE_KEY_SIZE,
            bytes.len()
        )));
    }

    // Convert bytes to array and create PrivateKeySigner
    let mut bytes_array = [0u8; SECP256K1_PRIVATE_KEY_SIZE];
    bytes_array.copy_from_slice(&bytes);

    // Create PrivateKeySigner from bytes (from_bytes expects &B256)
    let signer = PrivateKeySigner::from_bytes(&bytes_array.into()).map_err(|e| {
        KmsError::Crypto(format!("Invalid private key in NOX_KMS_WALLET_KEY: {}", e))
    })?;

    Ok(signer)
}

/// Convert a hex string (without 0x prefix) to a public key (ProjectivePoint).
///
/// Returns the public key or an error if the hex is invalid.
pub fn hex_to_point(hex: &str) -> KmsResult<ProjectivePoint> {
    let bytes =
        hex::decode(hex).map_err(|e| KmsError::Crypto(format!("Invalid hex string: {}", e)))?;
    let encoded = k256::EncodedPoint::from_bytes(&bytes)
        .map_err(|e| KmsError::Crypto(format!("Invalid public key encoding: {}", e)))?;
    Option::from(ProjectivePoint::from_encoded_point(&encoded))
        .ok_or_else(|| KmsError::Crypto("Invalid public key point".to_string()))
}

/// Convert a hex string (without 0x prefix) to an RSA public key.
///
/// Returns the RSA public key or an error if the hex is invalid.
pub fn hex_to_rsa_public_key(hex_spki: &str) -> KmsResult<RsaPublicKey> {
    let der_bytes = hex::decode(hex_spki)
        .map_err(|e| KmsError::Crypto(format!("Invalid hex encoding: {}", e)))?;
    RsaPublicKey::from_public_key_der(&der_bytes)
        .map_err(|e| KmsError::Crypto(format!("Invalid RSA SPKI DER: {}", e)))
}

/// Encrypt a shared secret (EC point's X-coordinate) with an RSA public key.
///
/// Extracts the X-coordinate and encrypts it using RSA-OAEP with SHA-256.
///
/// Returns the encrypted result as a hex string.
pub fn rsa_encrypt_shared_secret(
    shared_secret: &ProjectivePoint,
    rsa_public_key: &RsaPublicKey,
) -> KmsResult<String> {
    // Extract just the X-coordinate (32 bytes)
    let x_shared_secret = get_x_coordinate(shared_secret)?;
    let padding = Oaep::new::<Sha256>();
    let encrypted_x_shared_secret = rsa_public_key
        .encrypt(&mut OsRng, padding, &x_shared_secret)
        .map_err(|e| KmsError::Crypto(format!("Failed to encrypt shared secret: {}", e)))?;
    Ok(hex::encode(encrypted_x_shared_secret))
}

/// Extract X-coordinate from an EC point (32 bytes).
///
/// Returns the X-coordinate as a byte vector.
pub fn get_x_coordinate(p: &ProjectivePoint) -> KmsResult<Vec<u8>> {
    let enc = k256::EncodedPoint::from(p.to_affine());
    match enc.x() {
        Some(x) => Ok(x.to_vec()),
        None => Err(KmsError::Crypto(
            "Failed to extract X-coordinate".to_string(),
        )),
    }
}

/// Validate that the ephemeral public key is 33 bytes (66 hex characters).
/// Compressed SEC1 format: 0x02 or 0x03 prefix + 32 bytes X-coordinate.
pub fn validate_ephemeral_pub_key_size(hex: &str) -> KmsResult<()> {
    if hex.len() != EXPECTED_EPHEMERAL_PUB_KEY_HEX_LEN {
        return Err(KmsError::Crypto(format!(
            "Invalid ephemeral public key size: expected {} hex chars (33 bytes), got {}",
            EXPECTED_EPHEMERAL_PUB_KEY_HEX_LEN,
            hex.len()
        )));
    }
    Ok(())
}

/// Validate that the RSA public key data has at least 256 bytes (2048 bits).
pub fn validate_rsa_key_size(hex: &str) -> KmsResult<()> {
    if hex.len() < MIN_RSA_KEY_HEX_LEN {
        return Err(KmsError::Crypto(format!(
            "Invalid RSA public key size: expected at least {} hex chars (256 bytes), got {}",
            MIN_RSA_KEY_HEX_LEN,
            hex.len()
        )));
    }
    Ok(())
}
