use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};

#[derive(Zeroize,  Serialize, Deserialize)]
#[zeroize(drop)]
pub struct PrivateKeys {
    pub identity_private_key: [u8; 32],
    pub signed_prekeys: Vec<PrivateSignedPreKey>,
    pub one_time_prekeys: Vec<PrivateOneTimePreKey>,
}

#[derive(Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct PrivateSignedPreKey {
    pub id: u32,
    pub created_at: u64,
    pub private_key: [u8; 32],
    #[serde(with = "serde_arrays")]
    pub signature: [u8; 64],
}

#[derive(Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct PrivateOneTimePreKey {
    pub id: u32,
    pub created_at: u64,
    pub private_key: [u8; 32],
}