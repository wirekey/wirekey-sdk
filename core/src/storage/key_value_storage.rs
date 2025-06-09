use std::fmt::Debug;

/// Trait defining the interface for key-value storage.
///
/// This trait provides methods for basic key-value storage operations:
/// - `get`: Retrieve a value by key
/// - `put`: Store a key-value pair
/// - `delete`: Remove a key-value pair
/// - `exists`: Check if a key exists
/// - `scan_prefix`: Retrieve all key-value pairs with keys starting with a given prefix
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
    /// * `Result<Vec<u8>, anyhow::Error>` - The value as bytes if found, or an error if not found or if retrieval fails
    fn get(&self, key: &str) -> Result<Vec<u8>, anyhow::Error>;

    /// Stores a key-value pair.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to store
    /// * `value` - The value to store as bytes
    ///
    /// # Returns
    ///
    /// * `Result<(), anyhow::Error>` - Success or an error if storage fails
    fn put(&self, key: &str, value: &[u8]) -> Result<(), anyhow::Error>;

    /// Removes a key-value pair.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to remove
    ///
    /// # Returns
    ///
    /// * `Result<(), anyhow::Error>` - Success or an error if removal fails
    fn delete(&self, key: &str) -> Result<(), anyhow::Error>;

    /// Checks if a key exists.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to check
    ///
    /// # Returns
    ///
    /// * `Result<bool, anyhow::Error>` - True if the key exists, false if not, or an error if the check fails
    fn exists(&self, key: &str) -> Result<bool, anyhow::Error>;

    /// Retrieves all key-value pairs whose keys start with the given prefix.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The prefix to scan for
    ///
    /// # Returns
    ///
    /// * `Result<Vec<(String, Vec<u8>)>, anyhow::Error>` - A vector of key-value pairs where each key starts with the given prefix,
    ///   or an error if the scan fails
    fn scan_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, anyhow::Error>;
}
