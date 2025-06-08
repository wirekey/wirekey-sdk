use crate::api::error::ApiError;
use crate::api::prekey_bundle::{PreKeyBundle, PublicOneTimePreKey, PublicSignedPreKey};
use crate::api::private_keys::PrivateKeys;

/// API for managing encryption keys on the server
#[async_trait::async_trait]
pub trait KeyManagementApi {
    async fn get_prekey_bundle(&self, client_id: &str) -> Result<PreKeyBundle, ApiError>;
    async fn upload_signed_prekey(&self, prekey: PublicSignedPreKey) -> Result<(), ApiError>;
    async fn upload_one_time_prekeys(&self, prekeys: Vec<PublicOneTimePreKey>) -> Result<(), ApiError>;
    async fn get_prekey_count(&self) -> Result<u32, ApiError>;
    async fn get_private_keys(&self) -> Result<PrivateKeys, ApiError>;
}
