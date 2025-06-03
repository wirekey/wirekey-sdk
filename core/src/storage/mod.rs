use std::fmt::Debug;
use thiserror::Error;

pub type StorageResult<T> = Result<T, StorageError>;

mod local_storage;
mod error;
mod storage_manager;
mod memory_storage;

pub use local_storage::LocalStorage;
pub use error::StorageError;
pub use storage_manager::StorageManager;
pub use memory_storage::MemoryStorage;
