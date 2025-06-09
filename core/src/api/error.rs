use thiserror::Error;
use reqwest;
use serde_json;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    
    #[error("API returned error status {status}: {body}")]
    UnexpectedStatus {
        status: u16,
        body: String,
    },

    #[error("Failed to serialize request payload: {0}")]
    RequestSerialization(serde_json::Error),
    
    #[error("Failed to deserialize response payload: {0}")]
    ResponseDeserialization(serde_json::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}