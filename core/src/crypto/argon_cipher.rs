use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::{Aead}};
use argon2::{Argon2, password_hash::SaltString};
use rand::{rngs::OsRng, Rng};
use sha2::{Sha256, Digest};

/// Handles encryption and decryption of data using AES-GCM with an encryption key derived
/// from a secret using deterministic Argon2
#[derive(Debug)]
pub struct ArgonCipher {
    encryption_key: [u8; 32],
}

impl ArgonCipher {
    /// Create a new encryption instance with the given secret
    pub fn new(secret: &str) -> anyhow::Result<Self> {
        let encryption_key = Self::derive_key(secret)?;
        Ok(Self {
            encryption_key,
        })
    }

    /// Derive an encryption key from the provided secret using Argon2
    pub fn derive_key(secret: &str) -> anyhow::Result<[u8; 32]> {
        // Generate a salt from the secret
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let salt_bytes = hasher.finalize();

        // Convert to SaltString format
        let salt = SaltString::encode_b64(&salt_bytes[..16])
            .map_err(|e| anyhow::anyhow!("Failed to encode salt: {}", e))?;

        // Derive the encryption key using Argon2
        let mut output_key = [0u8; 32];
        Argon2::default().hash_password_into(
            secret.as_bytes(),
            salt.as_str().as_bytes(),
            &mut output_key,
        ).map_err(|e| anyhow::anyhow!("Failed to derive encryption key: {}", e))?;

        Ok(output_key)
    }

    /// Encrypt data using AES-GCM with a random nonce
    pub fn encrypt(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Generate a random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data using AES-GCM
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;
        let encrypted = cipher.encrypt(nonce, data)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Prepend the nonce to the encrypted data
        let mut result = Vec::with_capacity(nonce_bytes.len() + encrypted.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&encrypted);

        Ok(result)
    }

    /// Decrypt data using AES-GCM
    pub fn decrypt(&self, encrypted_data: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Ensure the data is at least as long as the nonce
        if encrypted_data.len() < 12 {
            return Err(anyhow::anyhow!("Encrypted data too short"));
        }

        // Extract the nonce and ciphertext
        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];

        // Decrypt the data using AES-GCM
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;
        let decrypted = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_valid_secret_creates_argon_cipher() {
        // Arrange
        let secret = "test_secret";

        // Act
        let result = ArgonCipher::new(secret);

        // Assert
        assert!(result.is_ok(), "Should successfully create ArgonCipher with valid secret");
        let cipher = result.unwrap();
        assert_eq!(cipher.encryption_key.len(), 32, "Encryption key should be 32 bytes");
    }

    #[test]
    fn derive_key_with_same_secret_produces_same_key() {
        // Arrange
        let secret = "test_secret";

        // Act
        let key1 = ArgonCipher::derive_key(secret).unwrap();
        let key2 = ArgonCipher::derive_key(secret).unwrap();

        // Assert
        assert_eq!(key1, key2, "Same secret should produce the same key");
    }

    #[test]
    fn derive_key_with_different_secrets_produces_different_keys() {
        // Arrange
        let secret1 = "test_secret_1";
        let secret2 = "test_secret_2";

        // Act
        let key1 = ArgonCipher::derive_key(secret1).unwrap();
        let key2 = ArgonCipher::derive_key(secret2).unwrap();

        // Assert
        assert_ne!(key1, key2, "Different secrets should produce different keys");
    }

    #[test]
    fn encrypt_produces_different_output_for_same_input() {
        // Arrange
        let cipher = ArgonCipher::new("test_secret").unwrap();
        let data = b"test data";

        // Act
        let encrypted1 = cipher.encrypt(data).unwrap();
        let encrypted2 = cipher.encrypt(data).unwrap();

        // Assert
        assert_ne!(encrypted1, encrypted2, "Encryption should produce different output for same input due to random nonce");
    }

    #[test]
    fn encrypt_decrypt_roundtrip_recovers_original_data() {
        // Arrange
        let cipher = ArgonCipher::new("test_secret").unwrap();
        let original_data = b"test data for encryption and decryption";

        // Act
        let encrypted = cipher.encrypt(original_data).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        // Assert
        assert_eq!(decrypted, original_data, "Decrypted data should match original data");
    }

    #[test]
    fn encrypt_decrypt_roundtrip_works_with_empty_data() {
        // Arrange
        let cipher = ArgonCipher::new("test_secret").unwrap();
        let empty_data = b"";

        // Act
        let encrypted = cipher.encrypt(empty_data).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        // Assert
        assert_eq!(decrypted, empty_data, "Decrypted empty data should match original empty data");
    }

    #[test]
    fn decrypt_with_too_short_data_returns_error() {
        // Arrange
        let cipher = ArgonCipher::new("test_secret").unwrap();
        let too_short_data = vec![1, 2, 3]; // Less than 12 bytes (nonce length)

        // Act
        let result = cipher.decrypt(&too_short_data);

        // Assert
        assert!(result.is_err(), "Decryption should fail with data shorter than nonce length");
        assert!(result.unwrap_err().to_string().contains("too short"), 
                "Error message should indicate data is too short");
    }

    #[test]
    fn decrypt_with_invalid_data_returns_error() {
        // Arrange
        let cipher = ArgonCipher::new("test_secret").unwrap();
        let mut invalid_data = vec![0; 20]; // 12 bytes for nonce + some data
        OsRng.fill(&mut invalid_data[..12]); // Fill nonce with random data

        // Act
        let result = cipher.decrypt(&invalid_data);

        // Assert
        assert!(result.is_err(), "Decryption should fail with invalid data");
    }

    #[test]
    fn decrypt_with_different_key_fails() {
        // Arrange
        let cipher1 = ArgonCipher::new("secret1").unwrap();
        let cipher2 = ArgonCipher::new("secret2").unwrap();
        let original_data = b"test data";

        // Act
        let encrypted = cipher1.encrypt(original_data).unwrap();
        let result = cipher2.decrypt(&encrypted);

        // Assert
        assert!(result.is_err(), "Decryption with different key should fail");
    }
}
