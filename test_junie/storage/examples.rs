//! # Storage Examples
//!
//! This module provides examples of how to use the storage abstractions with crypto types.

use serde::{Deserialize, Serialize};
use crate::crypto::key_pair::KeyPair;
use crate::storage::{KeyValueStorage, MemoryStorage, StorageResult, KeyValueStorageExt};

// Example of a serializable wrapper for KeyPair
// Since KeyPair doesn't implement Serialize/Deserialize, we need to create a wrapper
#[derive(Serialize, Deserialize)]
struct KeyPairWrapper {
    private_bytes: [u8; 32],
    public_bytes: [u8; 32],
}

impl From<&KeyPair> for KeyPairWrapper {
    fn from(key_pair: &KeyPair) -> Self {
        Self {
            private_bytes: key_pair.private_bytes(),
            public_bytes: key_pair.public_bytes(),
        }
    }
}

impl KeyPairWrapper {
    fn to_key_pair(&self) -> KeyPair {
        KeyPair::from_private_bytes(self.private_bytes)
    }
}

/// Example function demonstrating how to store and retrieve a KeyPair
pub fn store_and_retrieve_key_pair() -> StorageResult<()> {
    // Create a storage instance
    let storage = MemoryStorage::new();
    
    // Create a KeyPair
    let key_pair = KeyPair::generate();
    
    // Create a wrapper for the KeyPair
    let wrapper = KeyPairWrapper::from(&key_pair);
    
    // Store the KeyPair wrapper
    storage.put_typed("identity_key", &wrapper)?;
    
    // Retrieve the KeyPair wrapper
    let retrieved_wrapper: KeyPairWrapper = storage.get_typed("identity_key")?;
    
    // Convert back to KeyPair
    let retrieved_key_pair = retrieved_wrapper.to_key_pair();
    
    // Verify that the public key matches
    assert_eq!(key_pair.public_bytes(), retrieved_key_pair.public_bytes());
    
    println!("Successfully stored and retrieved a KeyPair!");
    Ok(())
}

/// Example of a client storage manager that handles storing and retrieving crypto types
pub struct ClientStorage {
    storage: Box<dyn KeyValueStorage>,
}

impl ClientStorage {
    /// Creates a new ClientStorage with the given storage backend
    pub fn new(storage: Box<dyn KeyValueStorage>) -> Self {
        Self { storage }
    }
    
    /// Stores the identity key
    pub fn store_identity_key(&self, key_pair: &KeyPair) -> StorageResult<()> {
        let wrapper = KeyPairWrapper::from(key_pair);
        self.storage.put_typed("identity_key", &wrapper)
    }
    
    /// Retrieves the identity key
    pub fn get_identity_key(&self) -> StorageResult<KeyPair> {
        let wrapper: KeyPairWrapper = self.storage.get_typed("identity_key")?;
        Ok(wrapper.to_key_pair())
    }
    
    /// Checks if the identity key exists
    pub fn has_identity_key(&self) -> StorageResult<bool> {
        self.storage.exists("identity_key")
    }
}

/// Example of how to use the ClientStorage
pub fn client_storage_example() -> StorageResult<()> {
    // Create a storage backend
    let storage = Box::new(MemoryStorage::new());
    
    // Create a client storage manager
    let client_storage = ClientStorage::new(storage);
    
    // Check if identity key exists (it shouldn't yet)
    let has_key = client_storage.has_identity_key()?;
    assert!(!has_key);
    
    // Generate and store an identity key
    let identity_key = KeyPair::generate();
    client_storage.store_identity_key(&identity_key)?;
    
    // Check if identity key exists now (it should)
    let has_key_now = client_storage.has_identity_key()?;
    assert!(has_key_now);
    
    // Retrieve the identity key
    let retrieved_key = client_storage.get_identity_key()?;
    
    // Verify that the public key matches
    assert_eq!(identity_key.public_bytes(), retrieved_key.public_bytes());
    
    println!("Successfully demonstrated ClientStorage!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_store_and_retrieve_key_pair() {
        let result = store_and_retrieve_key_pair();
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_client_storage() {
        let result = client_storage_example();
        assert!(result.is_ok());
    }
}