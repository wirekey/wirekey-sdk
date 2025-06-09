use super::*;
use std::collections::HashMap;
use std::sync::RwLock;
use anyhow::anyhow;

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

impl KeyValueStorage for MemoryStorage {
    fn get(&self, key: &str) -> Result<Vec<u8>, anyhow::Error> {
        let storage = self.storage.read().map_err(|e| {
            anyhow!("Failed to acquire read lock: {}", e)
        })?;

        storage.get(key).cloned().ok_or_else(|| anyhow!("Key not found: {}", key))
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<(), anyhow::Error> {
        let mut storage = self.storage.write().map_err(|e| {
            anyhow!("Failed to acquire write lock: {}", e)
        })?;

        storage.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), anyhow::Error> {
        let mut storage = self.storage.write().map_err(|e| {
            anyhow!("Failed to acquire write lock: {}", e)
        })?;

        storage.remove(key);
        Ok(())
    }

    fn exists(&self, key: &str) -> Result<bool, anyhow::Error> {
        let storage = self.storage.read().map_err(|e| {
            anyhow!("Failed to acquire read lock: {}", e)
        })?;

        Ok(storage.contains_key(key))
    }

    fn scan_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, anyhow::Error> {     
        let storage = self.storage.read().map_err(|e| {
            anyhow!("Failed to acquire read lock: {}", e)
        })?;

        let result: Vec<(String, Vec<u8>)> = storage
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();

        Ok(result)
    }
}
