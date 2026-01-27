use std::path::Path;

use alloy_signer_local::PrivateKeySigner;
use k256::{
    ProjectivePoint, Scalar as F, U256,
    elliptic_curve::{group::GroupEncoding, scalar::FromUintUnchecked, sec1::FromEncodedPoint},
};
use rand_core::OsRng;
use tracing::{debug, info, warn};

use crate::constants::{G, KEY_FILE_SIZE};
use crate::crypto::{
    generate_ec_key_pair, generate_sign_key, hex_to_point, hex_to_rsa_public_key,
    rsa_encrypt_shared_secret,
};
use crate::errors::{KmsError, KmsResult};
use crate::utils::truncate_hex;

#[derive(Clone)]
pub struct KmsService {
    pub private_key: F,
    pub public_key: ProjectivePoint,
    pub signer: PrivateKeySigner,
}

impl KmsService {
    /// Loads keys from files, or generates and saves new keys if files don't exist
    pub fn load_or_generate(
        key_file: &Path,
        keystore_file: &Path,
        keystore_password: &str,
    ) -> KmsResult<Self> {
        // Load or generate EC keys
        let (private_key, public_key) = if key_file.exists() {
            info!("Loading existing encryption keys from {:?}", key_file);
            Self::load_ec_keys_from_key_file(key_file)?
        } else {
            warn!("Key file {:?} not found, generating new EC keys", key_file);
            let keys = generate_ec_key_pair();
            Self::save_ec_keys_to_key_file(&keys, key_file)?;
            keys
        };

        // Load or generate signer
        let signer = if keystore_file.exists() {
            info!("Loading existing signer from {:?}", keystore_file);
            Self::load_signer_from_keystore(keystore_file, keystore_password)?
        } else {
            warn!(
                "Keystore file {:?} not found, generating new signer",
                keystore_file
            );
            let signer = generate_sign_key();
            Self::save_signer_to_keystore(&signer, keystore_file, keystore_password)?;
            signer
        };

        let service = Self {
            private_key,
            public_key,
            signer,
        };

        info!(
            "KMS ready - public key: {}, signer: {}",
            service.public_key_to_hex(),
            service.signer.address()
        );

        Ok(service)
    }

    /// Loads the signer from an encrypted keystore file
    fn load_signer_from_keystore(
        keystore_file: &Path,
        password: &str,
    ) -> KmsResult<PrivateKeySigner> {
        if !keystore_file.exists() {
            return Err(KmsError::Storage(format!(
                "Keystore file not found: {:?}",
                keystore_file
            )));
        }

        let signer = PrivateKeySigner::decrypt_keystore(keystore_file, password)
            .map_err(|e| KmsError::Storage(format!("Failed to decrypt keystore: {}", e)))?;

        info!(
            "Loaded signer from keystore {:?}, address: {}",
            keystore_file,
            signer.address()
        );

        Ok(signer)
    }

    /// Loads the EC keys from a binary file
    fn load_ec_keys_from_key_file(path: &Path) -> KmsResult<(F, ProjectivePoint)> {
        let data = std::fs::read(path)
            .map_err(|e| KmsError::Storage(format!("Failed to read key file: {}", e)))?;

        if data.len() != KEY_FILE_SIZE {
            return Err(KmsError::Storage(format!(
                "Invalid key file size: expected {} bytes, got {}",
                KEY_FILE_SIZE,
                data.len()
            )));
        }

        // Read private key (bytes 0-31)
        let mut private_key_bytes = [0u8; 32];
        private_key_bytes.copy_from_slice(&data[0..32]);
        let uint = U256::from_be_slice(&private_key_bytes);
        let private_key = F::from_uint_unchecked(uint);

        // Read public key (bytes 32-64)
        let encoded = k256::EncodedPoint::from_bytes(&data[32..65])
            .map_err(|e| KmsError::Storage(format!("Invalid public key encoding: {}", e)))?;
        let public_key = ProjectivePoint::from_encoded_point(&encoded);
        if public_key.is_none().into() {
            return Err(KmsError::Storage("Invalid public key point".to_string()));
        }
        let public_key = Option::from(ProjectivePoint::from_encoded_point(&encoded))
            .ok_or_else(|| KmsError::Storage("Invalid public key point".to_string()))?;

        // Verify that public key matches private key
        let computed_public = G * private_key;
        if computed_public != public_key {
            return Err(KmsError::Storage(
                "Public key does not match private key (file corrupted?)".to_string(),
            ));
        }

        Ok((private_key, public_key))
    }

    /// Saves EC keys to a binary file with secure permissions (600)
    fn save_ec_keys_to_key_file(keys: &(F, ProjectivePoint), path: &Path) -> KmsResult<()> {
        let (private_key, public_key) = keys;
        let mut data = Vec::with_capacity(KEY_FILE_SIZE);

        // Write private key (32 bytes)
        data.extend_from_slice(&private_key.to_bytes());

        // Write public key (33 bytes, compressed SEC1)
        data.extend_from_slice(&public_key.to_bytes());

        std::fs::write(path, &data)
            .map_err(|e| KmsError::Storage(format!("Failed to write key file: {}", e)))?;

        // Set file permissions to 600 (owner read/write only) on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, permissions)
                .map_err(|e| KmsError::Storage(format!("Failed to set file permissions: {}", e)))?;
        }

        info!("EC keys saved to {:?}", path);
        Ok(())
    }

    /// Saves the signer to an encrypted keystore file
    fn save_signer_to_keystore(
        signer: &PrivateKeySigner,
        keystore_file: &Path,
        password: &str,
    ) -> KmsResult<()> {
        let mut rng = OsRng;

        // Get the private key bytes from the signer
        let credential = signer.credential();
        let private_key_bytes = credential.to_bytes();

        // Get parent directory and filename from the path
        let dir = keystore_file.parent().unwrap_or(Path::new("."));
        let filename = keystore_file
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("signer.json");

        // Encrypt and save the keystore
        let (_wallet, _file_path) = PrivateKeySigner::encrypt_keystore(
            dir,
            &mut rng,
            private_key_bytes,
            password,
            Some(filename),
        )
        .map_err(|e| KmsError::Storage(format!("Failed to encrypt keystore: {}", e)))?;

        info!("Signer keystore saved to {:?}", keystore_file);

        // Set file permissions to 600 (owner read/write only) on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(keystore_file, permissions).map_err(|e| {
                KmsError::Storage(format!("Failed to set keystore permissions: {}", e))
            })?;
        }

        Ok(())
    }

    pub fn public_key_to_hex(&self) -> String {
        let bytes = &self.public_key.to_bytes();
        hex::encode(bytes)
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
