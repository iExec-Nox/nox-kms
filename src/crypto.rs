use alloy_signer_local::PrivateKeySigner;
use k256::{
    ProjectivePoint, Scalar as F,
    elliptic_curve::{Field, rand_core::OsRng, sec1::FromEncodedPoint},
};
use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey};
use sha2::Sha256;

use crate::constants::{EXPECTED_EPHEMERAL_PUB_KEY_HEX_LEN, G, MIN_RSA_KEY_HEX_LEN};
use crate::errors::{KmsError, KmsResult};

pub fn generate_ec_key_pair() -> (F, ProjectivePoint) {
    let private_key = F::random(&mut OsRng);
    let public_key = G * private_key;
    (private_key, public_key)
}

/// Generates a new random signing key
pub fn generate_sign_key() -> PrivateKeySigner {
    PrivateKeySigner::random()
}

/// Convert a hex string (without 0x prefix) to a public key (ProjectivePoint)
/// Returns the public key or an error if the hex is invalid
pub fn hex_to_point(hex: &str) -> KmsResult<ProjectivePoint> {
    let bytes =
        hex::decode(hex).map_err(|e| KmsError::Crypto(format!("Invalid hex string: {}", e)))?;
    let encoded = k256::EncodedPoint::from_bytes(&bytes)
        .map_err(|e| KmsError::Crypto(format!("Invalid public key encoding: {}", e)))?;
    Option::from(ProjectivePoint::from_encoded_point(&encoded))
        .ok_or_else(|| KmsError::Crypto("Invalid public key point".to_string()))
}

/// Convert a hex string (without 0x prefix) to an RSA public key
/// Returns the RSA public key or an error if the hex is invalid
pub fn hex_to_rsa_public_key(hex_spki: &str) -> KmsResult<RsaPublicKey> {
    let der_bytes = hex::decode(hex_spki)
        .map_err(|e| KmsError::Crypto(format!("Invalid hex encoding: {}", e)))?;
    RsaPublicKey::from_public_key_der(&der_bytes)
        .map_err(|e| KmsError::Crypto(format!("Invalid RSA SPKI DER: {}", e)))
}

/// Encrypt a shared secret (EC point's X-coordinate) with an RSA public key.
///
/// Extracts the X-coordinate and encrypts it using RSA-OAEP with SHA-256.
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
