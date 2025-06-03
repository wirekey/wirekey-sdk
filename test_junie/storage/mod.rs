//! # Storage Module
//!
//! This module provides abstractions for key-value storage that can be implemented
//! differently in different environments (native, WASM, etc.).

use std::fmt::Debug;
use thiserror::Error;

mod serialization;
pub use serialization::{serialize, deserialize, KeyValueStorageExt};

#[cfg(test)]
mod examples;

#[cfg(test)]
mod crypto_storage_tests;

/// Errors that can occur during storage operations.
#[derive(Error, Debug)]
pub enum StorageError {
    /// The requested key was not found in the storage.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// An error occurred during serialization or deserialization.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// An error occurred during a storage operation.
    #[error("Storage operation failed: {0}")]
    OperationFailed(String),

    /// The storage is not available or cannot be accessed.
    #[error("Storage unavailable: {0}")]
    StorageUnavailable(String),
}

/// Result type for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;

/// Trait defining the interface for key-value storage.
///
/// This trait provides methods for basic key-value storage operations:
/// - `get`: Retrieve a value by key
/// - `put`: Store a key-value pair
/// - `delete`: Remove a key-value pair
/// - `exists`: Check if a key exists
/// - `clear`: Remove all key-value pairs
///
/// Implementations of this trait can use different storage backends depending on the environment.
pub trait KeyValueStorage: Send + Sync + Debug {
    /// Retrieves a value by key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to retrieve
    ///
    /// # Returns
    ///
    /// * `StorageResult<Vec<u8>>` - The value as bytes if found, or an error if not found or if retrieval fails
    fn get(&self, key: &str) -> StorageResult<Vec<u8>>;

    /// Stores a key-value pair.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to store
    /// * `value` - The value to store as bytes
    ///
    /// # Returns
    ///
    /// * `StorageResult<()>` - Success or an error if storage fails
    fn put(&self, key: &str, value: &[u8]) -> StorageResult<()>;

    /// Removes a key-value pair.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to remove
    ///
    /// # Returns
    ///
    /// * `StorageResult<()>` - Success or an error if removal fails
    fn delete(&self, key: &str) -> StorageResult<()>;

    /// Checks if a key exists.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to check
    ///
    /// # Returns
    ///
    /// * `StorageResult<bool>` - True if the key exists, false if not, or an error if the check fails
    fn exists(&self, key: &str) -> StorageResult<bool>;

    /// Removes all key-value pairs.
    ///
    /// # Returns
    ///
    /// * `StorageResult<()>` - Success or an error if clearing fails
    fn clear(&self) -> StorageResult<()>;
}

/// A memory-based implementation of KeyValueStorage for testing and examples.
#[derive(Debug)]
pub struct MemoryStorage {
    storage: std::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>,
}

impl MemoryStorage {
    /// Creates a new empty MemoryStorage.
    pub fn new() -> Self {
        Self {
            storage: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl KeyValueStorage for MemoryStorage {
    fn get(&self, key: &str) -> StorageResult<Vec<u8>> {
        let storage = self.storage.read().map_err(|e| {
            StorageError::OperationFailed(format!("Failed to acquire read lock: {}", e))
        })?;

        storage.get(key).cloned().ok_or_else(|| StorageError::KeyNotFound(key.to_string()))
    }

    fn put(&self, key: &str, value: &[u8]) -> StorageResult<()> {
        let mut storage = self.storage.write().map_err(|e| {
            StorageError::OperationFailed(format!("Failed to acquire write lock: {}", e))
        })?;

        storage.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> StorageResult<()> {
        let mut storage = self.storage.write().map_err(|e| {
            StorageError::OperationFailed(format!("Failed to acquire write lock: {}", e))
        })?;

        storage.remove(key);
        Ok(())
    }

    fn exists(&self, key: &str) -> StorageResult<bool> {
        let storage = self.storage.read().map_err(|e| {
            StorageError::OperationFailed(format!("Failed to acquire read lock: {}", e))
        })?;

        Ok(storage.contains_key(key))
    }

    fn clear(&self) -> StorageResult<()> {
        let mut storage = self.storage.write().map_err(|e| {
            StorageError::OperationFailed(format!("Failed to acquire write lock: {}", e))
        })?;

        storage.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_storage_basic_operations() {
        let storage = MemoryStorage::new();

        // Test put and get
        let key = "test_key";
        let value = b"test_value";

        assert!(storage.put(key, value).is_ok());

        let retrieved = storage.get(key);
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), value);

        // Test exists
        let exists = storage.exists(key);
        assert!(exists.is_ok());
        assert!(exists.unwrap());

        // Test delete
        assert!(storage.delete(key).is_ok());

        let exists_after_delete = storage.exists(key);
        assert!(exists_after_delete.is_ok());
        assert!(!exists_after_delete.unwrap());

        // Test get after delete
        let retrieved_after_delete = storage.get(key);
        assert!(retrieved_after_delete.is_err());

        // Test clear
        assert!(storage.put(key, value).is_ok());
        assert!(storage.put("another_key", b"another_value").is_ok());

        assert!(storage.clear().is_ok());

        let exists_after_clear = storage.exists(key);
        assert!(exists_after_clear.is_ok());
        assert!(!exists_after_clear.unwrap());
    }
}
