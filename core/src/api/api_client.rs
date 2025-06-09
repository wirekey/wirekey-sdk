use reqwest::{Client, Response};
use crate::api::{ApiError, KeyManagementApi, PreKeyBundle, PublicOneTimePreKey, PublicSignedPreKey, PrivateKeys};
use crate::crypto::{ArgonCipher};

/// API client for communicating with the WireKey server
pub struct ApiClient {
    /// HTTP client for making requests
    client: Client,
    /// Base URL of the server
    server_url: String,
    /// Encryption for private keys
    cipher: ArgonCipher,
}

impl ApiClient {
    /// Create a new API client with the given server URL and secret for encrypting private keys
    pub fn new(server_url: String, secret: &str) -> Result<Self, ApiError> {
        let cipher = ArgonCipher::new(secret)?;
        Ok(Self {
            client: Client::new(),
            server_url,
            cipher,
        })
    }
}

async fn error_if_unsuccessful(response: Response) -> Result<Response, ApiError> {
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::UnexpectedStatus { status, body });
    }
    Ok(response)
}

#[async_trait::async_trait]
impl KeyManagementApi for ApiClient {
    async fn get_prekey_bundle(&self, client_id: &str) -> Result<PreKeyBundle, ApiError> {
        let url = format!("{}/prekey-bundle/{}", self.server_url, client_id);
        let response = self.client.get(&url).send().await?;
        let response = error_if_unsuccessful(response).await?;

        let prekey_bundle = response.json::<PreKeyBundle>().await?;
        Ok(prekey_bundle)
    }

    async fn upload_signed_prekey(&self, prekey: PublicSignedPreKey) -> Result<(), ApiError> {
        let url = format!("{}/signed-prekey", self.server_url);
        let response = self.client.post(&url).json(&prekey).send().await?;
        error_if_unsuccessful(response).await?;

        Ok(())
    }

    async fn upload_one_time_prekeys(&self, prekeys: Vec<PublicOneTimePreKey>) -> Result<(), ApiError> {
        let url = format!("{}/one-time-prekeys", self.server_url);
        let response = self.client.post(&url).json(&prekeys).send().await?;
        error_if_unsuccessful(response).await?;

        Ok(())
    }

    async fn get_prekey_count(&self) -> Result<u32, ApiError> {
        let url = format!("{}/prekey-count", self.server_url);
        let response = self.client.get(&url).send().await?;
        let response = error_if_unsuccessful(response).await?;

        let count = response.json::<u32>().await?;
        Ok(count)
    }

    async fn get_private_keys(&self) -> Result<PrivateKeys, ApiError> {
        let url = format!("{}/private-keys", self.server_url);
        let response = self.client.get(&url).send().await?;
        let response = error_if_unsuccessful(response).await?;

        // Get the encrypted private keys from the server
        let encrypted_data = response.bytes().await?;

        // Decrypt the private keys
        let decrypted_data = self.cipher.decrypt(&encrypted_data)?;

        // Deserialize the decrypted data into PrivateKeys
        let private_keys = serde_json::from_slice(&decrypted_data)
            .map_err(ApiError::ResponseDeserialization)?;

        Ok(private_keys)
    }

    async fn upload_private_keys(&self, private_keys: PrivateKeys) -> Result<(), ApiError> {
        let url = format!("{}/private-keys", self.server_url);

        // Serialize the private keys to JSON
        let serialized = serde_json::to_vec(&private_keys)
            .map_err(ApiError::RequestSerialization)?;

        // Encrypt the serialized private keys
        let encrypted_data = self.cipher.encrypt(&serialized)?;

        // Send the encrypted data to the server
        let response = self.client.post(&url)
            .body(encrypted_data)
            .header("Content-Type", "application/octet-stream")
            .send()
            .await?;

        error_if_unsuccessful(response).await?;

        Ok(())
    }
}
