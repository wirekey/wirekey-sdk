use crate::api::Error;
use crate::crypto::{ArgonCipher};
use hex;
use rand::rngs::OsRng;
use reqwest::{Client, RequestBuilder, Response};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use hmac::{Hmac, Mac};
use zeroize::Zeroize;
use crate::api::http_sender::{HttpSender, DefaultSender};
use crate::api::rng_provider::{RngProvider};

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SessionKey(pub Vec<u8>);

pub struct ApiClient<S: HttpSender = DefaultSender, R: RngProvider = OsRng> {
    pub(super) client: Client,
    pub(super) sender: S,
    pub(super) rng: Arc<Mutex<R>>,
    pub(super) server_url: String,
    pub(super) cipher: Arc<Mutex<Option<Arc<ArgonCipher>>>>,
    pub(super) session_key: Arc<Mutex<Option<SessionKey>>>,
    pub(super) session_token: Arc<Mutex<Option<String>>>,
    pub(super) client_id: String,
}

impl ApiClient<DefaultSender, OsRng> {
    pub fn new(server_url: String, client_id: &str) -> ApiClient<DefaultSender, OsRng> {
        Self::with_dependencies(server_url, client_id, DefaultSender, OsRng)
    }
}

impl<S: HttpSender, R: RngProvider> ApiClient<S, R> {
    pub fn with_dependencies(server_url: String, client_id: &str, sender: S, rng: R) -> ApiClient<S, R> {
        Self {
            client: Client::new(),
            sender,
            rng: Arc::new(Mutex::new(rng)),
            server_url,
            cipher: Arc::new(Mutex::new(None)),
            session_key: Arc::new(Mutex::new(None)),
            session_token: Arc::new(Mutex::new(None)),
            client_id: client_id.to_string(),
        }
    }

    pub(super) fn is_authenticated(&self) -> bool {
        let key_guard = self.session_key.lock().unwrap();
        key_guard.is_some()
    }

    pub(super) async fn send_get(&self, url: &str) -> Result<Response, Error> {
        if !self.is_authenticated() {
            return Err(Error::Unauthenticated);
        }

        let request = self.client.get(url);
        let authenticated =
            self.authenticate_request(url, "GET", None, request)?;

        let response = self.sender.send(authenticated)
            .await
            .map_err(anyhow::Error::from)?;

        let successful_response = error_if_unsuccessful(response).await?;
        Ok(successful_response)
    }

    pub(super) async fn send_post_json<T: Serialize>(
        &self,
        url: &str,
        payload: &T,
    ) -> Result<Response, Error> {
        let json = serde_json::to_vec(payload).map_err(Error::Serialization)?;
        self.send_post_with_body(url, "application/json", json).await
    }

    pub(super) async fn send_post_octet_stream(
        &self,
        url: &str,
        payload: Vec<u8>,
    ) -> Result<Response, Error> {
        self.send_post_with_body(url, "application/octet-stream", payload).await
    }

    async fn send_post_with_body(
        &self,
        url: &str,
        content_type: &str,
        payload: Vec<u8>,
    ) -> Result<Response, Error> {
        if !self.is_authenticated() {
            return Err(Error::Unauthenticated);
        }

        let request = self
            .client
            .post(url)
            .header("Content-Type", content_type);
        let authenticated =
            self.authenticate_request(url, "POST", Some(&payload), request)?;
        let with_payload = authenticated.body(payload);

        let response = self.sender.send(with_payload)
            .await
            .map_err(anyhow::Error::from)?;

        let successful_response = error_if_unsuccessful(response).await?;

        Ok(successful_response)
    }


    pub(super) fn authenticate_request(&self, url: &str, method: &str, payload: Option<&[u8]>, request: RequestBuilder) -> Result<RequestBuilder, Error> {
        let session_key_guard = self.session_key.lock().unwrap();
        let session_key = session_key_guard.as_ref().ok_or(Error::Unauthenticated)?;
        let session_token_guard = self.session_token.lock().unwrap();
        let session_token = session_token_guard.as_ref().ok_or(Error::Unauthenticated)?;

        let mut nonce = vec![0u8; 16];
        let mut rng = self.rng.lock().unwrap();
        rng.fill_bytes(&mut nonce);
        let nonce_hex = hex::encode(&nonce);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("Failed to get timestamp: {}", e))?
            .as_secs()
            .to_string();

        let mut message = format!("{}:{}:{}:{}:{}", url, method, &self.client_id, timestamp, nonce_hex);
        if let Some(payload) = payload {
            let mut hasher = Sha256::new();
            hasher.update(payload);
            let hash = hasher.finalize();
            let hash_hex = hex::encode(hash);
            message = format!("{}:{}", message, hash_hex);
        }

        let mut mac = Hmac::<Sha256>::new_from_slice(&session_key.0)
            .map_err(|e| anyhow::anyhow!("Failed to create HMAC: {}", e))?;
        mac.update(message.as_bytes());
        let signature = mac.finalize().into_bytes();
        let signature_hex = hex::encode(signature);

        // Add authentication headers        
        let request = request
            .header("Authorization", format!("Bearer {}", session_token))
            .header("X-Client-ID", &self.client_id)
            .header("X-Timestamp", &timestamp)
            .header("X-Nonce", &nonce_hex)
            .header("X-Signature", signature_hex);

        Ok(request)
    }
}

pub(super) async fn error_if_unsuccessful(response: Response) -> Result<Response, Error> {
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        return Err(Error::UnexpectedStatus { status, body });
    }
    Ok(response)
}
