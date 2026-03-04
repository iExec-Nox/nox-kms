use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{eip712_domain, sol};
use k256::{ProjectivePoint, Scalar as F, elliptic_curve::group::GroupEncoding};
use tracing::{debug, info};

use crate::constants::{EIP_712_DOMAIN_VERSION, PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME};
use crate::crypto::{
    hex_to_point, hex_to_rsa_public_key, import_ec_key_pair, import_wallet_key,
    rsa_encrypt_shared_secret,
};
use crate::errors::{KmsError, KmsResult};
use crate::utils::{serialize_bytes, truncate_hex};

sol! {
    #[derive(Debug)]
    struct DelegateResponseProof {
        string encryptedSharedSecret;
    }
}

#[derive(Clone)]
pub struct KmsService {
    pub private_key: F,
    pub public_key: ProjectivePoint,
    pub signer: PrivateKeySigner,
    pub chain_id: u32,
}

impl KmsService {
    /// Loads keys from environment variables
    pub fn load_keys(chain_id: u32, ecc_key: &str, wallet_key: &str) -> KmsResult<Self> {
        // Load EC keys from environment variable
        if ecc_key.is_empty() {
            return Err(KmsError::Crypto(
                "NOX_KMS_ECC_KEY environment variable not provided".to_string(),
            ));
        }
        info!("Importing EC keys from environment variable");
        let (private_key, public_key) = import_ec_key_pair(ecc_key)?;

        // Load signer from environment variable
        if wallet_key.is_empty() {
            return Err(KmsError::Crypto(
                "NOX_KMS_WALLET_KEY environment variable not provided".to_string(),
            ));
        }
        info!("Importing wallet key from environment variable");
        let signer = import_wallet_key(wallet_key)?;

        let service = Self {
            private_key,
            public_key,
            signer,
            chain_id,
        };

        info!(
            "KMS ready - public key: {}, signer: {}",
            serialize_bytes(&service.public_key.to_bytes()),
            service.signer.address()
        );

        Ok(service)
    }

    pub fn compute_delegate_response_proof(
        &self,
        encrypted_shared_secret: &str,
    ) -> KmsResult<String> {
        let domain = eip712_domain! {
            name: PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME,
            version: EIP_712_DOMAIN_VERSION,
            chain_id: u64::from(self.chain_id),
        };
        let proof = DelegateResponseProof {
            encryptedSharedSecret: encrypted_shared_secret.to_string(),
        };
        let signature = self
            .signer
            .sign_typed_data_sync(&proof, &domain)
            .map_err(|e| KmsError::Crypto(format!("Failed to sign DelegateResponseProof: {}", e)))?
            .as_bytes();

        Ok(serialize_bytes(&signature))
    }

    /// Computes and RSA-encrypts an ECDH shared secret for ECIES delegation.
    ///
    /// See [`handlers::delegate`] for full protocol details and input/output formats.
    ///
    /// # Arguments
    ///
    /// * `ephemeral_pub_key_hex` - Hex-encoded compressed SEC1 EC public key (33 bytes, no 0x prefix)
    /// * `target_rsa_pub_key_hex` - Hex-encoded RSA public key in SPKI DER format (no 0x prefix)
    ///
    /// # Returns
    ///
    /// Hex-encoded RSA-OAEP encrypted shared secret (no 0x prefix), or `KmsError::Crypto` on failure.
    pub fn ecies_delegate(
        &self,
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
        let shared_secret = ephemeral_pub_key * self.private_key;
        let result = rsa_encrypt_shared_secret(&shared_secret, &rsa_pub_key)?;

        debug!(
            encrypted_shared_secret = %truncate_hex(&result, 16),
            "ecies_delegate completed"
        );

        Ok(result)
    }
}
