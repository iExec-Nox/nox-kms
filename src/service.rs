use std::collections::HashMap;

use alloy::{
    primitives::{FixedBytes, hex},
    signers::{SignerSync, local::PrivateKeySigner},
    sol,
    sol_types::eip712_domain,
};
use k256::{ProjectivePoint, PublicKey, Scalar as F, elliptic_curve::group::GroupEncoding};
use tracing::{debug, info};

use crate::config::ChainConfig;
use crate::constants::{EIP_712_DOMAIN_VERSION, PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME};
use crate::crypto::{
    hex_to_point, hex_to_rsa_public_key, import_ec_key_pair, import_wallet_key,
    rsa_encrypt_shared_secret,
};
use crate::errors::{KmsError, KmsResult};
use crate::utils::truncate_hex;

sol! {
    #[derive(Debug)]
    struct DelegateResponseProof {
        string encryptedSharedSecret;
    }
}

#[derive(Clone)]
struct EcKeyPair {
    pub private_key: F,
    pub public_key: ProjectivePoint,
}

#[derive(Clone)]
pub struct KmsService {
    ec_keys: HashMap<u32, EcKeyPair>,
    pub signer: PrivateKeySigner,
}

impl KmsService {
    /// Loads keys from environment variables
    pub fn load_keys(chains: &HashMap<u32, ChainConfig>, wallet_key: &str) -> KmsResult<Self> {
        let ec_keys: HashMap<u32, EcKeyPair> = chains
            .iter()
            .map(|(chain_id, chain_config)| {
                // Load EC keys from environment variable
                info!("Importing EC keys from environment variable");
                let (private_key, public_key) = import_ec_key_pair(&chain_config.ecc_key)?;
                Ok((
                    *chain_id,
                    EcKeyPair {
                        private_key,
                        public_key,
                    },
                ))
            })
            .collect::<Result<HashMap<u32, EcKeyPair>, KmsError>>()?;

        // Load signer from environment variable
        info!("Importing wallet key from environment variable");
        let signer = import_wallet_key(wallet_key)?;

        let service = Self { ec_keys, signer };

        info!("KMS ready - signer: {}", service.signer.address());
        service.ec_keys.iter().for_each(|(chain_id, ec_key)| {
            info!(
                "KMS ready - chain {chain_id} - public key {}",
                hex::encode_prefixed(ec_key.public_key.to_bytes())
            )
        });

        Ok(service)
    }

    /// Asserts that the on-chain registered public key matches the local one.
    ///
    /// Decodes the on-chain bytes as a SEC1 secp256k1 point and compares it to
    /// `local` as a curve point (not as raw bytes), so a malformed or off-curve
    /// on-chain value is reported distinctly from a key mismatch.
    ///
    /// Returns `Ok(())` when the points are equal; `KmsError::Crypto` with a
    /// descriptive message otherwise.
    pub fn assert_onchain_kms_pubkey_matches(
        &self,
        onchain: &[u8],
        chain_id: &u32,
    ) -> KmsResult<()> {
        let onchain_point: ProjectivePoint = PublicKey::from_sec1_bytes(onchain)
            .map_err(|e| {
                KmsError::Crypto(format!(
                    "on-chain KMS public key ({} bytes) is not a valid SEC1 encoding: {e}",
                    onchain.len(),
                ))
            })?
            .to_projective();
        let local: ProjectivePoint = *self
            .ec_keys
            .get(chain_id)
            .map(|kp| &kp.public_key)
            .ok_or_else(|| {
                KmsError::Crypto(format!("No EC public key loaded for chain {chain_id}"))
            })?;
        if onchain_point != local {
            return Err(KmsError::Crypto(format!(
                "on-chain KMS public key {} does not match local-derived {}",
                hex::encode_prefixed(onchain),
                hex::encode_prefixed(local.to_bytes()),
            )));
        }
        Ok(())
    }

    pub fn compute_delegate_response_proof(
        &self,
        chain_id: u32,
        salt: FixedBytes<32>,
        encrypted_shared_secret: &str,
    ) -> KmsResult<String> {
        let domain = eip712_domain! {
            name: PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME,
            version: EIP_712_DOMAIN_VERSION,
            chain_id: u64::from(chain_id),
            salt: salt,
        };
        let proof = DelegateResponseProof {
            encryptedSharedSecret: encrypted_shared_secret.to_string(),
        };
        let signature = self
            .signer
            .sign_typed_data_sync(&proof, &domain)
            .map_err(|e| KmsError::Crypto(format!("Failed to sign DelegateResponseProof: {}", e)))?
            .as_bytes();

        Ok(hex::encode_prefixed(signature))
    }

    /// Computes and RSA-encrypts an ECDH shared secret for ECIES delegation.
    ///
    /// See [`super::handlers::delegate`] for full protocol details and input/output formats.
    ///
    /// # Arguments
    ///
    /// * `ephemeral_pub_key_hex` - Hex-encoded compressed SEC1 EC public key (33 bytes, no 0x prefix)
    /// * `target_rsa_pub_key_hex` - Hex-encoded RSA public key in SPKI DER format (no 0x prefix)
    ///
    /// # Returns
    ///
    /// Hex-encoded RSA-OAEP encrypted shared secret (no 0x prefix), or `KmsError::Crypto` on failure.
    #[tracing::instrument(skip_all)]
    pub fn ecies_delegate(
        &self,
        chain_id: u32,
        ephemeral_pub_key_hex: &str,
        target_rsa_pub_key_hex: &str,
    ) -> KmsResult<String> {
        debug!(
            ephemeral_pub_key = %truncate_hex(ephemeral_pub_key_hex, 16),
            target_pub_key = %truncate_hex(target_rsa_pub_key_hex, 16),
            "ecies_delegate called"
        );

        let ephemeral_pub_key = hex_to_point(ephemeral_pub_key_hex)?;
        let rsa_pub_key = hex_to_rsa_public_key(target_rsa_pub_key_hex)?;
        let shared_secret = ephemeral_pub_key * self.ec_keys[&chain_id].private_key;
        let result = rsa_encrypt_shared_secret(&shared_secret, &rsa_pub_key)?;

        debug!(
            encrypted_shared_secret = %truncate_hex(&result, 16),
            "ecies_delegate completed"
        );

        Ok(result)
    }
}
