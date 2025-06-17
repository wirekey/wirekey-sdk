use serde::de::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {    
    #[error("API returned error status {status}: {body}")]
    UnexpectedStatus {
        status: u16,
        body: String,
    },

    #[error("API endpoint requires authentication. Call register() or login() first.")]
    Unauthenticated,

    #[error("Failed to serialize request payload: {0}")]
    Serialization(serde_json::Error),

    #[error("Failed to deserialize response payload: {0}")]
    Deserialization(Box<dyn StdError + Send + Sync>),
    
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}