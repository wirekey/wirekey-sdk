use thiserror::Error;

/// Errors that can occur when interacting with the remote server API
#[derive(Error, Debug)]
pub enum RemoteServerError {
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    #[error("Server error: {0}")]
    ServerError(String),

    #[error("Not found: {0}")]
    NotFoundError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for remote server operations
pub type RemoteServerResult<T> = Result<T, RemoteServerError>;

/// Trait defining the remote server API for storing and retrieving key material
pub trait RemoteServerApi {
    /// Retrieve a key material bundle from the server
    fn get_key_material_bundle(&self, key: &str) -> RemoteServerResult<Option<Vec<u8>>>;

    /// Store a key material bundle on the server
    fn store_key_material_bundle(&self, key: &str, bundle_data: Vec<u8>) -> RemoteServerResult<()>;

    /// Delete a key material bundle from the server
    fn delete_key_material_bundle(&self, key: &str) -> RemoteServerResult<()>;
}
