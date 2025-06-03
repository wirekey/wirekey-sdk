//! # Storage Implementation for the Rust SDK
//!
//! This module provides a storage implementation for the Rust SDK using the sled database.

use std::fmt::Debug;
use std::path::Path;
use wirekey_core::storage::{KeyValueStorage, StorageError, StorageResult};

/// A storage implementation using the sled database.
#[derive(Debug)]
pub struct SledStorage {
    db: sled::Db,
}

impl SledStorage {
    /// Creates a new SledStorage instance with the given path.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the database directory
    ///
    /// # Returns
    ///
    /// * `StorageResult<Self>` - The new SledStorage instance, or an error if creation fails
    pub fn new<P: AsRef<Path>>(path: P) -> StorageResult<Self> {
        let db = sled::open(path).map_err(|e| {
            StorageError::StorageUnavailable(format!("Failed to open sled database: {}", e))
        })?;
        Ok(Self { db })
    }
}

impl KeyValueStorage for SledStorage {
    fn get(&self, key: &str) -> StorageResult<Vec<u8>> {
        self.db
            .get(key.as_bytes())
            .map_err(|e| {
                StorageError::OperationFailed(format!("Failed to get value: {}", e))
            })?
            .ok_or_else(|| StorageError::KeyNotFound(key.to_string()))
            .map(|ivec| ivec.to_vec())
    }

    fn put(&self, key: &str, value: &[u8]) -> StorageResult<()> {
        self.db
            .insert(key.as_bytes(), value)
            .map_err(|e| {
                StorageError::OperationFailed(format!("Failed to put value: {}", e))
            })?;
        self.db.flush().map_err(|e| {
            StorageError::OperationFailed(format!("Failed to flush database: {}", e))
        })?;
        Ok(())
    }

    fn delete(&self, key: &str) -> StorageResult<()> {
        self.db
            .remove(key.as_bytes())
            .map_err(|e| {
                StorageError::OperationFailed(format!("Failed to delete value: {}", e))
            })?;
        self.db.flush().map_err(|e| {
            StorageError::OperationFailed(format!("Failed to flush database: {}", e))
        })?;
        Ok(())
    }

    fn exists(&self, key: &str) -> StorageResult<bool> {
        self.db
            .contains_key(key.as_bytes())
            .map_err(|e| {
                StorageError::OperationFailed(format!("Failed to check if key exists: {}", e))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sled_storage_basic_operations() {
        // Create a temporary directory for the database
        let dir = tempdir().unwrap();
        let storage = SledStorage::new(dir.path()).unwrap();

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
        match retrieved_after_delete {
            Err(StorageError::KeyNotFound(_)) => (),
            _ => panic!("Expected KeyNotFound error"),
        }
    }
}