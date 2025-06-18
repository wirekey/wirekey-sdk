use std::sync::Arc;
use crate::api::api_client::{error_if_unsuccessful, SessionKey};
use crate::{ApiClient, Error};
use opaque_ke::{CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse};
use reqwest::{Response};
use serde_json::json;
use crate::api::http_send::HttpSend;
use crate::api::responses::{LoginFinishResponse};
use crate::crypto::ArgonCipher;
use crate::api::rng_provider::RngProvider;

const SERVER_ID: &[u8] = b"WireKey";

#[async_trait::async_trait]
pub trait AuthApi {
    async fn register(&self, client_id: &str, password: &str) -> Result<(), Error>;

    async fn login(&self, client_id: &str, password: &str) -> Result<(), Error>;

    async fn logout(&self) -> Result<(), Error>;
}

impl<S: HttpSend, R: RngProvider> CipherSuite for ApiClient<S, R> {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

impl<S: HttpSend, R: RngProvider> ApiClient<S, R> {
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
}

#[async_trait::async_trait]
impl<S: HttpSend, R: RngProvider> AuthApi for ApiClient<S, R> {
    async fn register(&self, client_id: &str, password: &str) -> Result<(), Error> {
        // Step 1: Create registration request
        let client_start_result = {
            let mut rng = self.rng.lock().unwrap();
            ClientRegistration::<Self>::start(&mut *rng, password.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to create OPAQUE registration request: {}", e))?
        };

        // Step 2: Send registration request to server
        let start_url = format!("{}/register/start", self.server_url);
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
                        client: Some(client_id.as_bytes()),
                        server: Some(SERVER_ID),
                    },
                    None,
                ),
            ).map_err(|e| anyhow::anyhow!("Failed to finish OPAQUE registration: {}", e))?
        };

        // Step 4: Send credential envelope to server
        let finish_url = format!("{}/register/finish", self.server_url);
        let finish_request_payload = client_finish_result.message.serialize();
        self.send_opaque_request(&finish_url, &finish_request_payload[..]).await?;

        // Step 5: Start key exchange
        self.login(client_id, password).await?;

        Ok(())
    }

    async fn login(&self, client_id: &str, password: &str) -> Result<(), Error> {
        // Step 1: Create credential request
        let client_start_result = {
            let mut rng = self.rng.lock().unwrap();
            ClientLogin::<Self>::start(&mut *rng, password.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to create OPAQUE login request: {}", e))?
        };

        // Step 2: Send credential request to server
        let start_url = format!("{}/login/start", self.server_url);
        let login_start_payload = client_start_result.message.serialize();
        let response = self.send_opaque_request(&start_url, &login_start_payload[..]).await?;
        let response_bytes = error_if_unsuccessful(response).await?.bytes().await.map_err(|e| anyhow::anyhow!("Failed to read response: {}", e))?;
        let server_start_response = CredentialResponse::<Self>::deserialize(&response_bytes[..]).map_err(|e| anyhow::anyhow!("Failed to deserialize response: {}", e))?;

        // Step 3: Use credential response to finish key exchange
        let client_login_finish_result = client_start_result.state.finish(
            password.as_bytes(),
            server_start_response,
            ClientLoginFinishParameters::new(
                None,
                Identifiers {
                    client: Some(client_id.as_bytes()),
                    server: Some(SERVER_ID),
                },
                None,
            ),
        ).map_err(|e| anyhow::anyhow!("Failed to finish OPAQUE login: {}", e))?;

        // Step 4: Obtain session token from server (this is no longer part of the OPAQUE protocol)
        let finish_url = format!("{}/login/finish", self.server_url);
        let finish_request =  self.client.get(&finish_url);
        let finish_response = self.sender.send(finish_request)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch session token: {}", e))?;
        let successful_response = error_if_unsuccessful(finish_response).await?;

        let session_token = successful_response.json::<LoginFinishResponse>().await
            .map_err(|e| Error::Deserialization(Box::new(e)))?.session_token;
        self.session_token.lock().unwrap().replace(session_token);

        let session_key = SessionKey(client_login_finish_result.session_key.to_vec());
        self.session_key.lock().unwrap().replace(session_key);

        let cipher = Arc::new(ArgonCipher::new(password)?);
        self.cipher.lock().unwrap().replace(cipher);

        Ok(())
    }

    async fn logout(&self) -> Result<(), Error> {
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
