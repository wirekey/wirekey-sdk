use thiserror::Error;

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