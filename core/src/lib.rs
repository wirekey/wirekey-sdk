//! # WireKey Core SDK
//!
//! This crate provides the core functionality for the WireKey E2E encryption SDK,
//! implementing the Signal protocol for secure messaging.

mod storage;
mod crypto;
mod api;

pub use api::{ApiClient, KeyManagementApi, Error};
