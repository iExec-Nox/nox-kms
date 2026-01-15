use crate::constants::{G, KEY_FILE_SIZE};
use crate::crypto::{
    generate_key_pair, hex_to_point, hex_to_rsa_public_key, rsa_encrypt_shared_secret,
};
use crate::errors::{KmsError, KmsResult};
use crate::utils::truncate_hex;
use k256::{
    ProjectivePoint, Scalar as F, U256,
    elliptic_curve::{group::GroupEncoding, scalar::FromUintUnchecked, sec1::FromEncodedPoint},
};
use std::path::Path;
use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct KmsService {
    pub private_key: F,
    pub public_key: ProjectivePoint,
}

impl KmsService {
    /// Loads keys from file, or generates and saves new keys if file doesn't exist
    pub fn load_or_generate(key_file: &Path) -> KmsResult<Self> {
        if key_file.exists() {
            info!("Loading existing keys from {:?}", key_file);
            let service = Self::load_from_file(key_file)?;
            info!(
                "Keys loaded successfully, public key: {}",
                service.public_key_to_hex()
            );
            Ok(service)
        } else {
            warn!("Key file {:?} not found, generating new keys", key_file);
            let service = Self::generate();
            service.save_to_file(key_file)?;
            info!(
                "New keys generated and saved to {:?}, public key: {}",
                key_file,
                service.public_key_to_hex()
            );
            Ok(service)
        }
    }

    fn generate() -> Self {
        let (private_key, public_key) = generate_key_pair();
        Self {
            private_key,
            public_key,
        }
    }

    /// Loads the keys from a binary file
    fn load_from_file(path: &Path) -> KmsResult<Self> {
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
        let public_key = public_key.unwrap();

        // Verify that public key matches private key
        let computed_public = G * private_key;
        if computed_public != public_key {
            return Err(KmsError::Storage(
                "Public key does not match private key (file corrupted?)".to_string(),
            ));
        }

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Saves the keys to a binary file with secure permissions (600)
    fn save_to_file(&self, path: &Path) -> KmsResult<()> {
        let mut data = Vec::with_capacity(KEY_FILE_SIZE);

        // Write private key (32 bytes)
        data.extend_from_slice(&self.private_key.to_bytes());

        // Write public key (33 bytes, compressed SEC1)
        data.extend_from_slice(&self.public_key.to_bytes());

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

        Ok(())
    }

    pub fn public_key_to_hex(&self) -> String {
        let bytes = &self.public_key.to_bytes();
        hex::encode(bytes)
    }

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
