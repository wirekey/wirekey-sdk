use serde::{Serialize, Deserialize};
use serde_arrays;

#[derive(Serialize, Deserialize)]
pub struct PreKeyBundle {
    #[serde(with = "serde_arrays")]
    pub identity_key: [u8; 32],
    pub signed_prekey: PublicSignedPreKey,
    pub one_time_prekey: Option<PublicOneTimePreKey>,
}

#[derive(Serialize, Deserialize)]
pub struct PublicSignedPreKey {
    pub id: u32,
    pub created_at: u64,
    #[serde(with = "serde_arrays")]
    pub public_key: [u8; 32],
    #[serde(with = "serde_arrays")]
    pub signature: [u8; 64],
}

#[derive(Serialize, Deserialize)]
pub struct PublicOneTimePreKey {
    pub id: u32,
    pub created_at: u64,
    #[serde(with = "serde_arrays")]
    pub public_key: [u8; 32],
}
