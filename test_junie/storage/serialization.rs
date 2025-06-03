//! # Serialization Helpers for Storage
//!
//! This module provides helper functions for serializing and deserializing
//! complex types to and from bytes for storage.

use serde::{Deserialize, Serialize};
use crate::storage::{StorageError, StorageResult};

/// Serializes a value to bytes using JSON serialization.
///
/// # Arguments
///
/// * `value` - The value to serialize
///
/// # Returns
///
/// * `StorageResult<Vec<u8>>` - The serialized value as bytes, or an error if serialization fails
pub fn serialize<T: Serialize>(value: &T) -> StorageResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| {
        StorageError::SerializationError(format!("Failed to serialize: {}", e))
    })
}

/// Deserializes bytes to a value using JSON deserialization.
///
/// # Arguments
///
/// * `bytes` - The bytes to deserialize
///
/// # Returns
///
/// * `StorageResult<T>` - The deserialized value, or an error if deserialization fails
pub fn deserialize<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> StorageResult<T> {
    serde_json::from_slice(bytes).map_err(|e| {
        StorageError::SerializationError(format!("Failed to deserialize: {}", e))
    })
}

/// Extension trait for KeyValueStorage to provide typed get and put methods.
pub trait KeyValueStorageExt {
    /// Retrieves a value by key and deserializes it to the specified type.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to retrieve
    ///
    /// # Returns
    ///
    /// * `StorageResult<T>` - The deserialized value if found, or an error if not found or if retrieval fails
    fn get_typed<T: for<'de> Deserialize<'de>>(&self, key: &str) -> StorageResult<T>;
    
    /// Serializes a value and stores it with the specified key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to store
    /// * `value` - The value to serialize and store
    ///
    /// # Returns
    ///
    /// * `StorageResult<()>` - Success or an error if storage fails
    fn put_typed<T: Serialize>(&self, key: &str, value: &T) -> StorageResult<()>;
}

impl<S: crate::storage::KeyValueStorage> KeyValueStorageExt for S {
    fn get_typed<T: for<'de> Deserialize<'de>>(&self, key: &str) -> StorageResult<T> {
        let bytes = self.get(key)?;
        deserialize(&bytes)
    }
    
    fn put_typed<T: Serialize>(&self, key: &str, value: &T) -> StorageResult<()> {
        let bytes = serialize(value)?;
        self.put(key, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use serde::{Deserialize, Serialize};
    
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestStruct {
        id: u32,
        name: String,
        data: Vec<u8>,
    }
    
    #[test]
    fn test_serialize_deserialize() {
        // Arrange
        let test_struct = TestStruct {
            id: 42,
            name: "Test".to_string(),
            data: vec![1, 2, 3, 4, 5],
        };
        
        // Act
        let serialized = serialize(&test_struct);
        assert!(serialized.is_ok());
        
        let bytes = serialized.unwrap();
        let deserialized: StorageResult<TestStruct> = deserialize(&bytes);
        
        // Assert
        assert!(deserialized.is_ok());
        assert_eq!(deserialized.unwrap(), test_struct);
    }
    
    #[test]
    fn test_storage_extension() {
        // Arrange
        let storage = MemoryStorage::new();
        let test_struct = TestStruct {
            id: 42,
            name: "Test".to_string(),
            data: vec![1, 2, 3, 4, 5],
        };
        
        // Act - Store using extension
        let result = storage.put_typed("test_key", &test_struct);
        assert!(result.is_ok());
        
        // Act - Retrieve using extension
        let retrieved: StorageResult<TestStruct> = storage.get_typed("test_key");
        
        // Assert
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), test_struct);
        
        // Act - Try to retrieve non-existent key
        let not_found: StorageResult<TestStruct> = storage.get_typed("non_existent_key");
        
        // Assert
        assert!(not_found.is_err());
        match not_found {
            Err(StorageError::KeyNotFound(_)) => (),
            _ => panic!("Expected KeyNotFound error"),
        }
    }
}