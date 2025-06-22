use crate::api::error::Error;
use crate::api::http_sender::HttpSender;
use crate::api::prekey_bundle::{PreKeyBundle, PublicOneTimePreKey, PublicSignedPreKey};
use crate::api::private_keys::PrivateKeys;
use crate::api::responses::PrekeyCountResponse;
use crate::api::rng_provider::RngProvider;
use crate::ApiClient;

/// API for managing encryption keys on the server
#[async_trait::async_trait]
pub trait KeyManagementApi {
    async fn get_prekey_bundle(&self, client_id: &str) -> Result<PreKeyBundle, Error>;
    async fn upload_signed_prekey(&self, prekey: PublicSignedPreKey) -> Result<(), Error>;
    async fn upload_one_time_prekeys(&self, prekeys: Vec<PublicOneTimePreKey>) -> Result<(), Error>;
    async fn get_prekey_count(&self) -> Result<u32, Error>;
    async fn get_private_keys(&self) -> Result<PrivateKeys, Error>;
    async fn upload_private_keys(&self, private_keys: PrivateKeys) -> Result<(), Error>;
}

#[async_trait::async_trait]
impl<S: HttpSender, R: RngProvider>KeyManagementApi for ApiClient<S, R> {
    async fn get_prekey_bundle(&self, client_id: &str) -> Result<PreKeyBundle, Error> {
        let url = format!("{}/prekey-bundle/{}", self.server_url, client_id);
        let response = self.send_get(&url).await?;

        let prekey_bundle = response.json::<PreKeyBundle>().await
            .map_err(|e| Error::Deserialization(Box::new(e)))?;
        Ok(prekey_bundle)
    }

    async fn upload_signed_prekey(&self, prekey: PublicSignedPreKey) -> Result<(), Error> {
        let url = format!("{}/signed-prekey", self.server_url);
        _ = self.send_post_json(&url, &prekey).await?;

        Ok(())
    }

    async fn upload_one_time_prekeys(&self, prekeys: Vec<PublicOneTimePreKey>) -> Result<(), Error> {
        let url = format!("{}/one-time-prekeys", self.server_url);
        _ = self.send_post_json(&url, &prekeys).await?;

        Ok(())
    }

    async fn get_prekey_count(&self) -> Result<u32, Error> {
        let url = format!("{}/prekey-count", self.server_url);
        let response = self.send_get(&url).await?;

        let count = response.json::<PrekeyCountResponse>().await
            .map_err(|e| Error::Deserialization(Box::new(e)))?.count;

        Ok(count)
    }

    async fn get_private_keys(&self) -> Result<PrivateKeys, Error> {
        let url = format!("{}/private-keys", self.server_url);
        let response = self.send_get(&url).await?;
        let encrypted = response.bytes().await.map_err(anyhow::Error::from)?;

        let cipher = {
            let guard = self.cipher.lock().unwrap();
            guard.as_ref().cloned().ok_or(Error::Unauthenticated)?
        };
        
        let decrypted = cipher.decrypt(&encrypted)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt response payload: {}", e))?;
        let private_keys = serde_json::from_slice(&decrypted)
            .map_err(|e| Error::Deserialization(Box::new(e)))?;

        Ok(private_keys)
    }

    async fn upload_private_keys(&self, private_keys: PrivateKeys) -> Result<(), Error> {
        let cipher = {
            let guard = self.cipher.lock().unwrap();
            guard.as_ref().cloned().ok_or(Error::Unauthenticated)?
        };

        let serialized = serde_json::to_vec(&private_keys)
            .map_err(|e| anyhow::anyhow!("Failed to serialize request payload: {}", e))?;
        let encrypted = cipher.encrypt(&serialized)?;

        let url = format!("{}/private-keys", self.server_url);
        _ = self.send_post_octet_stream(&url, encrypted).await?;

        Ok(())
    }
}