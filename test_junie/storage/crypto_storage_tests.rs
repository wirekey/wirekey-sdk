//! # Crypto Storage Tests
//!
//! This module contains comprehensive tests for using the storage abstractions with crypto types.

use serde::{Deserialize, Serialize};
use crate::crypto::key_pair::KeyPair;
use crate::crypto::one_time_prekey_record::OneTimePreKeyRecord;
use crate::crypto::signed_prekey_record::SignedPreKeyRecord;
use crate::storage::{KeyValueStorage, MemoryStorage, StorageResult, KeyValueStorageExt};

// Serializable wrappers for crypto types

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

#[derive(Serialize, Deserialize)]
struct OneTimePreKeyRecordWrapper {
    id: u32,
    key_pair: KeyPairWrapper,
}

impl From<&OneTimePreKeyRecord> for OneTimePreKeyRecordWrapper {
    fn from(record: &OneTimePreKeyRecord) -> Self {
        Self {
            id: record.id,
            key_pair: KeyPairWrapper::from(&record.key_pair),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SignedPreKeyRecordWrapper {
    id: u32,
    created_at: u64,
    key_pair: KeyPairWrapper,
    signature: [u8; 64],
}

impl From<&SignedPreKeyRecord> for SignedPreKeyRecordWrapper {
    fn from(record: &SignedPreKeyRecord) -> Self {
        Self {
            id: record.id,
            created_at: record.created_at,
            key_pair: KeyPairWrapper::from(&record.key_pair),
            signature: record.signature,
        }
    }
}

// Test storage manager for crypto types

struct CryptoStorage {
    storage: Box<dyn KeyValueStorage>,
}

impl CryptoStorage {
    fn new(storage: Box<dyn KeyValueStorage>) -> Self {
        Self { storage }
    }
    
    // Identity key methods
    
    fn store_identity_key(&self, key_pair: &KeyPair) -> StorageResult<()> {
        let wrapper = KeyPairWrapper::from(key_pair);
        self.storage.put_typed("identity_key", &wrapper)
    }
    
    fn get_identity_key(&self) -> StorageResult<KeyPair> {
        let wrapper: KeyPairWrapper = self.storage.get_typed("identity_key")?;
        Ok(wrapper.to_key_pair())
    }
    
    fn has_identity_key(&self) -> StorageResult<bool> {
        self.storage.exists("identity_key")
    }
    
    // Signed prekey methods
    
    fn store_signed_prekey(&self, record: &SignedPreKeyRecord) -> StorageResult<()> {
        let wrapper = SignedPreKeyRecordWrapper::from(record);
        let key = format!("signed_prekey_{}", record.id);
        self.storage.put_typed(&key, &wrapper)
    }
    
    fn get_signed_prekey(&self, id: u32) -> StorageResult<SignedPreKeyRecordWrapper> {
        let key = format!("signed_prekey_{}", id);
        self.storage.get_typed(&key)
    }
    
    // One-time prekey methods
    
    fn store_one_time_prekey(&self, record: &OneTimePreKeyRecord) -> StorageResult<()> {
        let wrapper = OneTimePreKeyRecordWrapper::from(record);
        let key = format!("one_time_prekey_{}", record.id);
        self.storage.put_typed(&key, &wrapper)
    }
    
    fn get_one_time_prekey(&self, id: u32) -> StorageResult<OneTimePreKeyRecordWrapper> {
        let key = format!("one_time_prekey_{}", id);
        self.storage.get_typed(&key)
    }
    
    fn delete_one_time_prekey(&self, id: u32) -> StorageResult<()> {
        let key = format!("one_time_prekey_{}", id);
        self.storage.delete(&key)
    }
}

#[test]
fn test_crypto_storage_identity_key() {
    // Arrange
    let storage = Box::new(MemoryStorage::new());
    let crypto_storage = CryptoStorage::new(storage);
    
    // Act & Assert - Initially no identity key
    let has_key = crypto_storage.has_identity_key().unwrap();
    assert!(!has_key);
    
    // Act - Store identity key
    let identity_key = KeyPair::generate();
    let store_result = crypto_storage.store_identity_key(&identity_key);
    assert!(store_result.is_ok());
    
    // Act & Assert - Now has identity key
    let has_key_now = crypto_storage.has_identity_key().unwrap();
    assert!(has_key_now);
    
    // Act - Retrieve identity key
    let retrieved_key = crypto_storage.get_identity_key().unwrap();
    
    // Assert - Keys match
    assert_eq!(identity_key.public_bytes(), retrieved_key.public_bytes());
}

#[test]
fn test_crypto_storage_signed_prekey() {
    // Arrange
    let storage = Box::new(MemoryStorage::new());
    let crypto_storage = CryptoStorage::new(storage);
    let identity_key = KeyPair::generate();
    
    // Act - Generate and store signed prekey
    let signed_prekey = SignedPreKeyRecord::generate(&identity_key);
    let id = signed_prekey.id;
    let store_result = crypto_storage.store_signed_prekey(&signed_prekey);
    assert!(store_result.is_ok());
    
    // Act - Retrieve signed prekey
    let retrieved_wrapper = crypto_storage.get_signed_prekey(id).unwrap();
    
    // Assert - IDs match
    assert_eq!(id, retrieved_wrapper.id);
    assert_eq!(signed_prekey.created_at, retrieved_wrapper.created_at);
    
    // Assert - Signatures match
    assert_eq!(signed_prekey.signature, retrieved_wrapper.signature);
}

#[test]
fn test_crypto_storage_one_time_prekey() {
    // Arrange
    let storage = Box::new(MemoryStorage::new());
    let crypto_storage = CryptoStorage::new(storage);
    
    // Act - Generate and store one-time prekey
    let one_time_prekey = OneTimePreKeyRecord::generate();
    let id = one_time_prekey.id;
    let store_result = crypto_storage.store_one_time_prekey(&one_time_prekey);
    assert!(store_result.is_ok());
    
    // Act - Retrieve one-time prekey
    let retrieved_wrapper = crypto_storage.get_one_time_prekey(id).unwrap();
    
    // Assert - IDs match
    assert_eq!(id, retrieved_wrapper.id);
    
    // Act - Delete one-time prekey
    let delete_result = crypto_storage.delete_one_time_prekey(id);
    assert!(delete_result.is_ok());
    
    // Act & Assert - Prekey should be gone
    let get_result = crypto_storage.get_one_time_prekey(id);
    assert!(get_result.is_err());
}