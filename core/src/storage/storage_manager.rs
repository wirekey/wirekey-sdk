use std::fmt::Debug;
use std::sync::Arc;

use anyhow::anyhow;
use crate::crypto::{ArgonCipher};
use crate::storage::{KeyValueStorage};

/// A wrapper around a `LocalStorage` implementation that encrypts/decrypts data
/// as it is written to/read from the storage.
///
/// This struct uses AES-GCM for encryption and Argon2 for key derivation.
/// The encryption key is derived from the provided secret using Argon2.
///
/// Each value is stored with a random nonce prepended to it, which is used for decryption.
#[derive(Debug)]
pub struct StorageManager {
    storage: Arc<dyn KeyValueStorage>,
    cipher: ArgonCipher,
    bucket: String,
}

impl StorageManager {
    pub fn new(bucket: &str, secret: &str, storage: Arc<dyn KeyValueStorage>) -> Result<Self, anyhow::Error> {
        let cipher = ArgonCipher::new(secret)?;
        Ok(Self {
            storage,
            cipher,
            bucket: bucket.to_string(),
        })
    }
}

impl KeyValueStorage for StorageManager {
    fn get(&self, key: &str) -> Result<Vec<u8>, anyhow::Error> {
        let prefixed_key = format!("{}{}", self.bucket, key);
        let encrypted = self.storage.get(&prefixed_key)?;
        self.cipher.decrypt(&encrypted)
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<(), anyhow::Error> {
        let prefixed_key = format!("{}{}", self.bucket, key);
        let encrypted = self.cipher.encrypt(value)?;
        self.storage.put(&prefixed_key, &encrypted)
    }

    fn delete(&self, key: &str) -> Result<(), anyhow::Error> {
        let prefixed_key = format!("{}{}", self.bucket, key);
        self.storage.delete(&prefixed_key)
    }

    fn exists(&self, key: &str) -> Result<bool, anyhow::Error> {
        let prefixed_key = format!("{}{}", self.bucket, key);
        self.storage.exists(&prefixed_key)
    }

    fn scan_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, anyhow::Error> {
        let prefixed_prefix = format!("{}{}", self.bucket, prefix);
        let encrypted_items = self.storage.scan_prefix(&prefixed_prefix)?;

        // Process each item: remove bucket prefix from key and decrypt value
        let mut result = Vec::with_capacity(encrypted_items.len());
        for (key, encrypted_value) in encrypted_items {
            // Remove bucket prefix from key
            let original_key = key.strip_prefix(&self.bucket)
                .ok_or_else(|| anyhow!("Key does not have expected bucket prefix: {}", key))?
                .to_string();

            // Decrypt the value
            let decrypted_value = self.cipher.decrypt(&encrypted_value)?;

            result.push((original_key, decrypted_value));
        }

        Ok(result)
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
        let result = StorageManager::new(bucket, secret, memory_storage);

        // Assert
        assert!(result.is_ok());
    }

    #[test]
    fn derive_key_with_same_secret_returns_identical_keys() {
        // Arrange
        let secret = "test_secret";

        // Act
        let key1 = ArgonCipher::derive_key(secret).unwrap();
        let key2 = ArgonCipher::derive_key(secret).unwrap();

        // Assert
        assert_eq!(key1, key2, "Keys derived from the same secret should be identical");
    }

    #[test]
    fn derive_key_with_different_secrets_returns_different_keys() {
        // Arrange
        let secret1 = "test_secret_1";
        let secret2 = "test_secret_2";

        // Act
        let key1 = ArgonCipher::derive_key(secret1).unwrap();
        let key2 = ArgonCipher::derive_key(secret2).unwrap();

        // Assert
        assert_ne!(key1, key2, "Keys derived from different secrets should be different");
    }

    #[test]
    fn encrypt_decrypt_with_valid_data_returns_original_data() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";
        let storage_manager = StorageManager::new(bucket, secret, memory_storage).unwrap();
        let original_data = b"This is a test message";

        // Act
        let encrypted = storage_manager.cipher.encrypt(original_data).unwrap();
        let decrypted = storage_manager.cipher.decrypt(&encrypted).unwrap();

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
        let storage_manager = StorageManager::new(bucket, secret, memory_storage).unwrap();
        let invalid_data = vec![1, 2, 3]; // Too short to contain a nonce

        // Act
        let result = storage_manager.cipher.decrypt(&invalid_data);

        // Assert
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_msg = err.to_string();
        assert!(err_msg.contains("too short"), "Error should mention data being too short");
    }

    #[test]
    fn decrypt_with_tampered_data_returns_error() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";
        let storage_manager = StorageManager::new(bucket, secret, memory_storage).unwrap();
        let original_data = b"This is a test message";
        let mut encrypted = storage_manager.cipher.encrypt(original_data).unwrap();

        // Tamper with the encrypted data (not the nonce)
        if encrypted.len() > 15 {
            encrypted[15] ^= 0xFF; // Flip all bits at position 15
        }

        // Act
        let result = storage_manager.cipher.decrypt(&encrypted);

        // Assert
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_msg = err.to_string();
        assert!(err_msg.contains("Decryption failed"), "Error should mention decryption failure");
    }

    #[test]
    fn storage_put_and_get_with_valid_data_succeeds() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";
        let storage_manager = StorageManager::new(bucket, secret, memory_storage.clone()).unwrap();
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
        let storage_manager = StorageManager::new(bucket, secret, memory_storage.clone()).unwrap();
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
        let storage_manager = StorageManager::new(bucket, secret, memory_storage.clone()).unwrap();
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
        let storage_manager = StorageManager::new(bucket, secret, memory_storage.clone()).unwrap();
        let key = "test_key";
        let value = b"test_value";
        storage_manager.put(key, value).unwrap();
        storage_manager.delete(key).unwrap();

        // Act & Assert - Get after delete
        let retrieved_after_delete = storage_manager.get(key);
        assert!(retrieved_after_delete.is_err());
        let err = retrieved_after_delete.unwrap_err();
        let err_msg = err.to_string();
        assert!(err_msg.contains("not found") || err_msg.contains("Key not found"), 
                "Error should indicate key not found");
    }

    #[test]
    fn storage_managers_with_same_secret_different_storages_maintain_isolation() {
        // Arrange
        let memory_storage1 = Arc::new(MemoryStorage::new());
        let memory_storage2 = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";
        let storage_manager1 = StorageManager::new(bucket, secret, memory_storage1).unwrap();
        let _storage_manager2 = StorageManager::new(bucket, secret, memory_storage2.clone()).unwrap();
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
        let storage_manager1 = StorageManager::new(bucket1, secret, memory_storage.clone()).unwrap();
        let storage_manager2 = StorageManager::new(bucket2, secret, memory_storage.clone()).unwrap();
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
        let storage_manager1 = StorageManager::new(bucket, secret1, memory_storage1.clone()).unwrap();
        let storage_manager2 = StorageManager::new(bucket, secret2, memory_storage2.clone()).unwrap();
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

    #[test]
    fn scan_prefix_returns_matching_items() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";
        let storage_manager = StorageManager::new(bucket, secret, memory_storage).unwrap();

        // Add some test data
        storage_manager.put("prefix_key1", b"value1").unwrap();
        storage_manager.put("prefix_key2", b"value2").unwrap();
        storage_manager.put("other_key", b"value3").unwrap();

        // Act
        let result = storage_manager.scan_prefix("prefix_").unwrap();

        // Assert
        assert_eq!(result.len(), 2, "Should return 2 items with prefix 'prefix_'");

        // Sort results for deterministic comparison
        let mut sorted_result = result;
        sorted_result.sort_by(|(a, _), (b, _)| a.cmp(b));

        assert_eq!(sorted_result[0].0, "prefix_key1");
        assert_eq!(sorted_result[0].1, b"value1");
        assert_eq!(sorted_result[1].0, "prefix_key2");
        assert_eq!(sorted_result[1].1, b"value2");
    }

    #[test]
    fn scan_prefix_with_no_matches_returns_empty_vector() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket = "test_bucket_";
        let storage_manager = StorageManager::new(bucket, secret, memory_storage).unwrap();

        // Add some test data that doesn't match the prefix
        storage_manager.put("key1", b"value1").unwrap();
        storage_manager.put("key2", b"value2").unwrap();

        // Act
        let result = storage_manager.scan_prefix("nonexistent_").unwrap();

        // Assert
        assert_eq!(result.len(), 0, "Should return empty vector for non-matching prefix");
    }

    #[test]
    fn scan_prefix_with_different_buckets_maintains_isolation() {
        // Arrange
        let memory_storage = Arc::new(MemoryStorage::new());
        let secret = "test_secret";
        let bucket1 = "bucket1_";
        let bucket2 = "bucket2_";
        let storage_manager1 = StorageManager::new(bucket1, secret, memory_storage.clone()).unwrap();
        let storage_manager2 = StorageManager::new(bucket2, secret, memory_storage).unwrap();

        // Add data to both storage managers with the same key prefix
        storage_manager1.put("test_key", b"value1").unwrap();
        storage_manager2.put("test_key", b"value2").unwrap();

        // Act
        let result1 = storage_manager1.scan_prefix("test_").unwrap();
        let result2 = storage_manager2.scan_prefix("test_").unwrap();

        // Assert
        assert_eq!(result1.len(), 1, "Should return 1 item for bucket1");
        assert_eq!(result2.len(), 1, "Should return 1 item for bucket2");

        assert_eq!(result1[0].0, "test_key");
        assert_eq!(result1[0].1, b"value1");
        assert_eq!(result2[0].0, "test_key");
        assert_eq!(result2[0].1, b"value2");
    }
}
