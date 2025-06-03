use std::fmt::Debug;
use std::sync::Arc;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::{Aead}};
use argon2::{Argon2, password_hash::SaltString};
use rand::{rngs::OsRng, Rng};
use sha2::{Sha256, Digest};

use crate::storage::{LocalStorage, StorageResult, StorageError};

/// A wrapper around a `LocalStorage` implementation that encrypts/decrypts data
/// as it is written to/read from the storage.
///
/// This struct uses AES-GCM for encryption and Argon2 for key derivation.
/// The encryption key is derived from the provided secret using Argon2.
///
/// Each value is stored with a random nonce prepended to it, which is used for decryption.
#[derive(Debug)]
pub struct StorageManager {
    storage: Arc<dyn LocalStorage>,
    encryption_key: [u8; 32],
    bucket: String,
}

impl StorageManager {
    pub fn new(storage: Arc<dyn LocalStorage>, secret: &str, bucket: &str) -> StorageResult<Self> {
        let encryption_key = Self::derive_key(secret)?;
        Ok(Self {
            storage,
            encryption_key,
            bucket: bucket.to_string(),
        })
    }

    fn derive_key(secret: &str) -> StorageResult<[u8; 32]> {
        // Generate a salt from the secret
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let salt_bytes = hasher.finalize();

        // Convert to SaltString format
        let salt = SaltString::encode_b64(&salt_bytes[..16])
            .expect("Failed to encode salt");

        // Derive the encryption key using Argon2
        let mut output_key = [0u8; 32];
        Argon2::default().hash_password_into(
            secret.as_bytes(),
            salt.as_str().as_bytes(),
            &mut output_key,
        ).map_err(|e| StorageError::OperationFailed(format!("Failed to derive encryption key: {}", e)))?;

        Ok(output_key)
    }

    fn encrypt(&self, data: &[u8]) -> StorageResult<Vec<u8>> {
        // Generate a random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data using AES-GCM.
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| StorageError::OperationFailed(format!("Failed to create cipher: {}", e)))?;        
        let encrypted = cipher.encrypt(nonce, data)
            .map_err(|e| StorageError::OperationFailed(format!("Encryption failed: {}", e)))?;

        // Prepend the nonce to the encrypted data
        let mut result = Vec::with_capacity(nonce_bytes.len() + encrypted.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&encrypted);

        Ok(result)
    }

    fn decrypt(&self, encrypted_data: &[u8]) -> StorageResult<Vec<u8>> {
        // Ensure the data is at least as long as the nonce
        if encrypted_data.len() < 12 {
            return Err(StorageError::OperationFailed("Encrypted data too short".to_string()));
        }

        // Extract the nonce and ciphertext
        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];

        // Decrypt the data using AES-GCM
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| StorageError::OperationFailed(format!("Failed to create cipher: {}", e)))?;        
        let decrypted = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| StorageError::OperationFailed(format!("Decryption failed: {}", e)))?;

        Ok(decrypted)
    }
}

impl LocalStorage for StorageManager {
    fn get(&self, key: &str) -> StorageResult<Vec<u8>> {
        let prefixed_key = format!("{}{}", self.bucket, key);
        let encrypted = self.storage.get(&prefixed_key)?;
        self.decrypt(&encrypted)
    }

    fn put(&self, key: &str, value: &[u8]) -> StorageResult<()> {
        let prefixed_key = format!("{}{}", self.bucket, key);
        let encrypted = self.encrypt(value)?;        
        self.storage.put(&prefixed_key, &encrypted)
    }

    fn delete(&self, key: &str) -> StorageResult<()> {
        let prefixed_key = format!("{}{}", self.bucket, key);
        self.storage.delete(&prefixed_key)
    }

    fn exists(&self, key: &str) -> StorageResult<bool> {
        let prefixed_key = format!("{}{}", self.bucket, key);
        self.storage.exists(&prefixed_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::MemoryStorage;
    use super::*;
    use std::sync::Arc;

    #[test]
    fn new_with_valid_secret_creates_storage_manager() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";

        // Act
        let result = StorageManager::new(memory_storage, secret, bucket);

        // Assert
        assert!(result.is_ok());
    }

    #[test]
    fn derive_key_with_same_secret_returns_identical_keys() {
        // Arrange
        let secret = "test_secret";

        // Act
        let key1 = StorageManager::derive_key(secret).unwrap();
        let key2 = StorageManager::derive_key(secret).unwrap();

        // Assert
        assert_eq!(key1, key2, "Keys derived from the same secret should be identical");
    }

    #[test]
    fn derive_key_with_different_secrets_returns_different_keys() {
        // Arrange
        let secret1 = "test_secret_1";
        let secret2 = "test_secret_2";

        // Act
        let key1 = StorageManager::derive_key(secret1).unwrap();
        let key2 = StorageManager::derive_key(secret2).unwrap();

        // Assert
        assert_ne!(key1, key2, "Keys derived from different secrets should be different");
    }

    #[test]
    fn encrypt_decrypt_with_valid_data_returns_original_data() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";
        let storage_manager = StorageManager::new(memory_storage, secret, bucket).unwrap();
        let original_data = b"This is a test message";

        // Act
        let encrypted = storage_manager.encrypt(original_data).unwrap();
        let decrypted = storage_manager.decrypt(&encrypted).unwrap();

        // Assert
        assert_ne!(encrypted, original_data, "Encrypted data should be different from original");
        assert!(encrypted.len() > original_data.len(), "Encrypted data should be longer due to nonce");
        assert_eq!(decrypted, original_data, "Decrypted data should match original");
    }

    #[test]
    fn decrypt_with_invalid_data_returns_error() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";
        let storage_manager = StorageManager::new(memory_storage, secret, bucket).unwrap();
        let invalid_data = vec![1, 2, 3]; // Too short to contain a nonce

        // Act
        let result = storage_manager.decrypt(&invalid_data);

        // Assert
        assert!(result.is_err());
        match result {
            Err(StorageError::OperationFailed(msg)) => {
                assert!(msg.contains("too short"), "Error should mention data being too short");
            }
            _ => panic!("Expected OperationFailed error"),
        }
    }

    #[test]
    fn decrypt_with_tampered_data_returns_error() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";
        let storage_manager = StorageManager::new(memory_storage, secret, bucket).unwrap();
        let original_data = b"This is a test message";
        let mut encrypted = storage_manager.encrypt(original_data).unwrap();

        // Tamper with the encrypted data (not the nonce)
        if encrypted.len() > 15 {
            encrypted[15] ^= 0xFF; // Flip all bits at position 15
        }

        // Act
        let result = storage_manager.decrypt(&encrypted);

        // Assert
        assert!(result.is_err());
        match result {
            Err(StorageError::OperationFailed(msg)) => {
                assert!(msg.contains("Decryption failed"), "Error should mention decryption failure");
            }
            _ => panic!("Expected OperationFailed error"),
        }
    }

    #[test]
    fn storage_put_and_get_with_valid_data_succeeds() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";
        let storage_manager = StorageManager::new(memory_storage.clone(), secret, bucket).unwrap();
        let key = "test_key";
        let value = b"test_value";

        // Act & Assert - Put and Get
        assert!(storage_manager.put(key, value).is_ok());

        // Verify the data is encrypted in the underlying storage
        let prefixed_key = format!("{}{}", bucket, key);
        let raw_stored = memory_storage.get(&prefixed_key).unwrap();
        assert_ne!(raw_stored, value, "Stored data should be encrypted");

        let retrieved = storage_manager.get(key);
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), value, "Retrieved data should match original after decryption");
    }

    #[test]
    fn storage_exists_with_stored_key_returns_true() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";
        let storage_manager = StorageManager::new(memory_storage.clone(), secret, bucket).unwrap();
        let key = "test_key";
        let value = b"test_value";
        storage_manager.put(key, value).unwrap();

        // Act & Assert
        let exists = storage_manager.exists(key);
        assert!(exists.is_ok());
        assert!(exists.unwrap(), "Key should exist");
    }

    #[test]
    fn storage_delete_with_existing_key_removes_entry() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";
        let storage_manager = StorageManager::new(memory_storage.clone(), secret, bucket).unwrap();
        let key = "test_key";
        let value = b"test_value";
        storage_manager.put(key, value).unwrap();

        // Act & Assert - Delete
        assert!(storage_manager.delete(key).is_ok());

        let exists_after_delete = storage_manager.exists(key);
        assert!(exists_after_delete.is_ok());
        assert!(!exists_after_delete.unwrap(), "Key should not exist after deletion");
    }

    #[test]
    fn storage_get_with_deleted_key_returns_error() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";
        let storage_manager = StorageManager::new(memory_storage.clone(), secret, bucket).unwrap();
        let key = "test_key";
        let value = b"test_value";
        storage_manager.put(key, value).unwrap();
        storage_manager.delete(key).unwrap();

        // Act & Assert - Get after delete
        let retrieved_after_delete = storage_manager.get(key);
        assert!(retrieved_after_delete.is_err());
        match retrieved_after_delete {
            Err(StorageError::KeyNotFound(_)) => (),
            _ => panic!("Expected KeyNotFound error"),
        }
    }

    #[test]
    fn storage_managers_with_same_secret_different_storages_maintain_isolation() {
        // Arrange
        let memory_storage1 = Arc::new(MemoryStorage::new());
        let memory_storage2 = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";
        let storage_manager1 = StorageManager::new(memory_storage1, secret, bucket).unwrap();
        let _storage_manager2 = StorageManager::new(memory_storage2.clone(), secret, bucket).unwrap();
        let key = "test_key";
        let value = b"test_value";

        // Act
        storage_manager1.put(key, value).unwrap();

        // The key in the second storage would be prefixed with the bucket
        let prefixed_key = format!("{}{}", bucket, key);
        let encrypted = memory_storage2.get(&prefixed_key);

        // Assert
        assert!(encrypted.is_err(), "Key should not exist in second storage");
    }

    #[test]
    fn storage_managers_with_different_buckets_maintain_isolation() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket1 = "bucket1_";
        let bucket2 = "bucket2_";
        let storage_manager1 = StorageManager::new(memory_storage.clone(), secret, bucket1).unwrap();
        let storage_manager2 = StorageManager::new(memory_storage.clone(), secret, bucket2).unwrap();
        let key = "test_key";
        let value1 = b"test_value_1";
        let value2 = b"test_value_2";

        // Act
        storage_manager1.put(key, value1).unwrap();
        storage_manager2.put(key, value2).unwrap();

        // Assert
        let retrieved1 = storage_manager1.get(key).unwrap();
        let retrieved2 = storage_manager2.get(key).unwrap();

        assert_eq!(retrieved1, value1, "Value from bucket1 should match what was stored in bucket1");
        assert_eq!(retrieved2, value2, "Value from bucket2 should match what was stored in bucket2");
        assert_ne!(retrieved1, retrieved2, "Values from different buckets should be different");

        // Verify the keys are stored with different prefixes in the underlying storage
        let prefixed_key1 = format!("{}{}", bucket1, key);
        let prefixed_key2 = format!("{}{}", bucket2, key);

        assert!(memory_storage.exists(&prefixed_key1).unwrap(), "Key should exist with bucket1 prefix");
        assert!(memory_storage.exists(&prefixed_key2).unwrap(), "Key should exist with bucket2 prefix");
    }

    #[test]
    fn storage_managers_with_different_secrets_produce_different_encryptions() {
        // Arrange
        let memory_storage1 = Arc::new(MemoryStorage::new());
        let memory_storage2 = Arc::new(MemoryStorage::new());
        let secret1 = "test_secret_1";
        let secret2 = "test_secret_2";
        let bucket = "test_bucket_";
        let storage_manager1 = StorageManager::new(memory_storage1.clone(), secret1, bucket).unwrap();
        let storage_manager2 = StorageManager::new(memory_storage2.clone(), secret2, bucket).unwrap();
        let key = "test_key";
        let value = b"test_value";

        // Act
        storage_manager1.put(key, value).unwrap();
        storage_manager2.put(key, value).unwrap();

        // The keys in the storage are prefixed with the bucket
        let prefixed_key = format!("{}{}", bucket, key);
        let encrypted1 = memory_storage1.get(&prefixed_key).unwrap();
        let encrypted2 = memory_storage2.get(&prefixed_key).unwrap();

        // Assert
        assert_ne!(encrypted1, encrypted2, "Encryptions with different secrets should be different");
    }
}
