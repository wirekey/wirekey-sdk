use aes_gcm::aead::rand_core::Error;
use rand::{CryptoRng, RngCore};
use rand::rngs::OsRng;

pub trait RngProvider: RngCore + CryptoRng + Send + Sync {}

impl RngProvider for OsRng {}