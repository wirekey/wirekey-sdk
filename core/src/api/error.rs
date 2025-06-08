use thiserror::Error;
use std::io;
use reqwest;
use serde_json;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Network IO error: {0}")]
    Network(#[from] io::Error),

    #[error("API returned error status {status}: {body}")]
    Response {
        status: u16,
        body: String,
    },

    #[error("Failed to parse server response: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("Authentication failed")]
    Auth,

    #[error("Permission denied")]
    Permission,

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Timeout")]
    Timeout,

    #[error("Other error: {0}")]
    Other(String),
}