use std::fmt::Debug;
use crate::storage::StorageResult;

/// Trait defining the interface for local key-value storage.
///
/// This trait provides methods for basic key-value storage operations:
/// - `get`: Retrieve a value by key
/// - `put`: Store a key-value pair
/// - `delete`: Remove a key-value pair
/// - `exists`: Check if a key exists
///
/// Implementations of this trait can use different storage backends depending on the environment.
pub trait LocalStorage: Send + Sync + Debug {
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
}