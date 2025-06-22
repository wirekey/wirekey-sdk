use crate::api::api_client::{error_if_unsuccessful, SessionKey};
use crate::api::http_sender::HttpSender;
use crate::api::rng_provider::RngProvider;
use crate::crypto::ArgonCipher;
use crate::{ApiClient, Error};
use argon2::password_hash::SaltString;
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use opaque_ke::{CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse};
use reqwest::Response;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(super) const SERVER_ID: &[u8] = b"WireKey";

#[async_trait::async_trait]
pub trait AuthApi {
    async fn authenticate(&self, client_id: &str, password: &str) -> Result<(), Error>;

    async fn logout(&self) -> Result<(), Error>;
}

impl<S: HttpSender, R: RngProvider> CipherSuite for ApiClient<S, R> {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

#[async_trait::async_trait]
impl<S: HttpSender, R: RngProvider> AuthApi for ApiClient<S, R> {
    async fn authenticate(&self, username: &str, password: &str) -> Result<(), Error> {
        if username.is_empty() {
            return Err(anyhow::anyhow!("Username cannot be empty").into());
        }
        if password.is_empty() {
            return Err(anyhow::anyhow!("Password cannot be empty").into());       
        }

        let anonymous_id = self.anonymize_username(username, password)?;

        // First try to log in using the anonymized username
        let login_result = self.login(&anonymous_id, password).await;

        // If login fails with 401 Unauthorized, try to register
        match login_result {
            Ok(()) => Ok(()), // Login successful
            Err(Error::UnexpectedStatus { status, .. }) if status == 401 => {
                // Login failed with 401 Unauthorized, try to register and then login
                self.register(&anonymous_id, password).await?;
                self.login(&anonymous_id, password).await
            }
            Err(e) => Err(e), // Other error, propagate it
        }
    }

    async fn logout(&self) -> Result<(), Error> {
        if !self.is_authenticated() {
            return Ok(());
        }

        let url = format!("{}/logout", self.server_url);
        _ = self.send_post_json(&url, &json!({ })).await?;

        let mut session_token_guard = self.session_token.lock().unwrap();
        session_token_guard.take();

        let mut session_key_guard = self.session_key.lock().unwrap();
        session_key_guard.take();

        let mut cipher_guard = self.cipher.lock().unwrap();
        cipher_guard.take();
        Ok(())
    }
}

impl<S: HttpSender, R: RngProvider> ApiClient<S, R> {
    fn anonymize_username(&self, username: &str, password: &str) -> Result<String, Error> {
        // Create input that includes client_id for global uniqueness
        let input = format!("{}:{}", self.client_id, username);

        // Use password as salt material
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let salt_hash = hasher.finalize();

        // Create salt string from first 16 bytes of the hash
        let salt = SaltString::encode_b64(&salt_hash[..16])
            .map_err(|e| anyhow::anyhow!("Failed to encode salt: {}", e))?;

        // Use Argon2 to hash the input with the password-derived salt
        let mut output_hash = [0u8; 32];
        Argon2::default().hash_password_into(
            input.as_bytes(),
            salt.as_str().as_bytes(),
            &mut output_hash,
        ).map_err(|e| anyhow::anyhow!("Failed to hash username: {}", e))?;

        // Encode as URL-safe base64 (no padding, URL-safe characters)
        let anonymous_id = URL_SAFE_NO_PAD.encode(&output_hash);

        Ok(anonymous_id)
    }


    async fn send_opaque_request(&self, url: &str, payload: &[u8]) -> Result<Response, Error> {
        let request = self.client.post(url)
            .body(payload.to_vec())
            .header("Content-Type", "application/octet-stream");

        let response = self.sender.send(request)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send OPAQUE request: {}", e))?;

        let successful_response = error_if_unsuccessful(response).await?;
        Ok(successful_response)
    }

    async fn register(&self, user_id: &str, password: &str) -> Result<(), Error> {
        // Step 1: Create registration request
        let client_start_result = {
            let mut rng = self.rng.lock().unwrap();
            ClientRegistration::<Self>::start(&mut *rng, password.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to create OPAQUE registration request: {}", e))?
        };

        // Step 2: Send registration request to server
        let start_url = format!("{}/register/start/{}", self.server_url, user_id);
        let start_request_payload = client_start_result.message.serialize();
        let response = self.send_opaque_request(&start_url, &start_request_payload[..]).await?;
        let response_bytes = response.bytes().await.map_err(|e| anyhow::anyhow!("Failed to read response: {}", e))?;
        let server_start_response = RegistrationResponse::<Self>::deserialize(&response_bytes[..]).map_err(|e| anyhow::anyhow!("Failed to deserialize response: {}", e))?;

         // Step 3: Use registration response to crete credential envelope
        let client_finish_result = {
            let mut rng = self.rng.lock().unwrap();
            client_start_result.state.finish(
                &mut *rng,
                password.as_bytes(),
                server_start_response,
                ClientRegistrationFinishParameters::new(
                    Identifiers {
                        client: Some(user_id.as_bytes()),
                        server: Some(SERVER_ID),
                    },
                    None,
                ),
            ).map_err(|e| anyhow::anyhow!("Failed to finish OPAQUE registration: {}", e))?
        };

        // Step 4: Send credential envelope to server
        let finish_url = format!("{}/register/finish/{}", self.server_url, user_id);
        let finish_request_payload = client_finish_result.message.serialize();
        self.send_opaque_request(&finish_url, &finish_request_payload[..]).await?;

        Ok(())
    }

    async fn login(&self, user_id: &str, password: &str) -> Result<(), Error> {
        // Step 1: Create credential request
        let client_start_result = {
            let mut rng = self.rng.lock().unwrap();
            ClientLogin::<Self>::start(&mut *rng, password.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to create OPAQUE login request: {}", e))?
        };

        // Step 2: Send credential request to server
        let url = format!("{}/login/{}", self.server_url, user_id);
        let login_start_payload = client_start_result.message.serialize();

        let response = self.send_opaque_request(&url, &login_start_payload[..]).await?;
        let response_bytes = error_if_unsuccessful(response).await?.bytes().await.map_err(|e| anyhow::anyhow!("Failed to read response: {}", e))?;

        // Extract session token (first part) and OPAQUE response (rest)
        let session_token_len = response_bytes[0] as usize;
        if response_bytes.len() < 1 + session_token_len {
            return Err(anyhow::anyhow!("Invalid response format").into());
        }

        let session_token = String::from_utf8(response_bytes[1..1 + session_token_len].to_vec())
            .map_err(|e| anyhow::anyhow!("Invalid session token format: {}", e))?;
        let opaque_response_bytes = &response_bytes[1 + session_token_len..];

        let server_start_response = CredentialResponse::<Self>::deserialize(opaque_response_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize response: {}", e))?;

        // Step 3: Use credential response to finish key exchange
        let client_login_finish_result = client_start_result.state.finish(
            password.as_bytes(),
            server_start_response,
            ClientLoginFinishParameters::new(
                None,
                Identifiers {
                    client: Some(user_id.as_bytes()),
                    server: Some(SERVER_ID),
                },
                None,
            ),
        ).map_err(|e| anyhow::anyhow!("Failed to finish OPAQUE login: {}", e))?;

        // Step 4: Store authentication state
        self.session_token.lock().unwrap().replace(session_token);

        let session_key = SessionKey(client_login_finish_result.session_key.to_vec());
        self.session_key.lock().unwrap().replace(session_key);

        let cipher = Arc::new(ArgonCipher::new(password)?);
        self.cipher.lock().unwrap().replace(cipher);

        Ok(())
    }
}
