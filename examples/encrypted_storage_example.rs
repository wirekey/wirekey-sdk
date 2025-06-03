use std::sync::Arc;
use wirekey_core::storage::{LocalStorage, EncryptedStorage, StorageResult};

// A simple in-memory storage implementation for demonstration purposes
#[derive(Debug)]
struct SimpleMemoryStorage {
    data: std::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>,
}

impl SimpleMemoryStorage {
    fn new() -> Self {
        Self {
            data: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl LocalStorage for SimpleMemoryStorage {
    fn get(&self, key: &str) -> StorageResult<Vec<u8>> {
        let data = self.data.read().unwrap();
        match data.get(key) {
            Some(value) => Ok(value.clone()),
            None => Err(wirekey_core::storage::StorageError::KeyNotFound(key.to_string())),
        }
    }

    fn put(&self, key: &str, value: &[u8]) -> StorageResult<()> {
        let mut data = self.data.write().unwrap();
        data.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> StorageResult<()> {
        let mut data = self.data.write().unwrap();
        data.remove(key);
        Ok(())
    }

    fn exists(&self, key: &str) -> StorageResult<bool> {
        let data = self.data.read().unwrap();
        Ok(data.contains_key(key))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a base storage implementation
    let base_storage = Arc::new(SimpleMemoryStorage::new());
    
    // Create an encrypted storage wrapper with a secret
    let secret = "my_secure_secret";
    let encrypted_storage = EncryptedStorage::new(base_storage.clone(), secret);
    
    // Store some sensitive data
    let key = "sensitive_data";
    let value = b"This is sensitive information that should be encrypted";
    encrypted_storage.put(key, value)?;
    
    println!("Stored sensitive data with key: {}", key);
    
    // Verify that the data in the underlying storage is encrypted
    let raw_data = base_storage.get(key)?;
    println!("Raw data in storage (encrypted): {:?}", raw_data);
    println!("Raw data length: {} bytes", raw_data.len());
    println!("Original data length: {} bytes", value.len());
    
    // Retrieve and decrypt the data
    let retrieved_data = encrypted_storage.get(key)?;
    println!("Retrieved and decrypted data: {}", String::from_utf8_lossy(&retrieved_data));
    
    // Create another encrypted storage with a different secret
    let different_secret = "different_secret";
    let another_storage = EncryptedStorage::new(base_storage.clone(), different_secret);
    
    // Try to retrieve the data with the wrong secret
    match another_storage.get(key) {
        Ok(_) => println!("Successfully decrypted with wrong secret (this shouldn't happen)"),
        Err(e) => println!("Failed to decrypt with wrong secret (expected): {}", e),
    }
    
    // Delete the data
    encrypted_storage.delete(key)?;
    println!("Deleted sensitive data with key: {}", key);
    
    // Verify it's gone
    match encrypted_storage.get(key) {
        Ok(_) => println!("Data still exists (unexpected)"),
        Err(e) => println!("Data is gone (expected): {}", e),
    }
    
    Ok(())
}