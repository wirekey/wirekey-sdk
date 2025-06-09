use std::fmt::Debug;

mod key_value_storage;
mod error;
mod storage_manager;
mod memory_storage;

pub use key_value_storage::KeyValueStorage;
pub use storage_manager::StorageManager;
pub use memory_storage::MemoryStorage;
