use super::*;
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Debug)]
pub struct MemoryStorage {
    storage: RwLock<HashMap<String, Vec<u8>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            storage: RwLock::new(HashMap::new()),
        }
    }
}

impl LocalStorage for MemoryStorage {
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
}