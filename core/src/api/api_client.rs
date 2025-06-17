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
use crate::api::http_send::{HttpSend, DefaultSender};
use crate::api::rng_provider::{RngProvider};

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SessionKey(pub Vec<u8>);

pub struct ApiClient<S: HttpSend = DefaultSender, R: RngProvider = OsRng> {
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

impl<S: HttpSend, R: RngProvider> ApiClient<S, R> {
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


    fn authenticate_request(&self, url: &str, method: &str, payload: Option<&[u8]>, request: RequestBuilder) -> Result<RequestBuilder, Error> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::{StatusCode};
    use serde_json::json;
    use crate::api::mock_rng_provider::MockRngProvider;
    use crate::api::mock_sender::{create_error_response, create_ok_response, MockSender};

    #[test]
    fn new_creates_api_client_with_expected_values() {
        // Arrange
        let server_url = "https://example.com".to_string();
        let client_id = "test_client";

        // Act
        let client = ApiClient::new(server_url.clone(), client_id);

        // Assert
        assert_eq!(client.server_url, server_url);
        assert_eq!(client.client_id, client_id);
        assert!(client.cipher.lock().unwrap().is_none());
        assert!(client.session_key.lock().unwrap().is_none());
        assert!(client.session_token.lock().unwrap().is_none());
    }

    #[test]
    fn with_sender_creates_api_client_with_custom_sender() {
        // Arrange
        let server_url = "https://example.com".to_string();
        let client_id = "test_client";
        let sender = MockSender::new(vec![]);

        // Act
        let client = ApiClient::with_dependencies(server_url.clone(), client_id, sender, OsRng);

        // Assert
        assert_eq!(client.server_url, server_url);
        assert_eq!(client.client_id, client_id);
        assert!(client.cipher.lock().unwrap().is_none());
        assert!(client.session_key.lock().unwrap().is_none());
        assert!(client.session_token.lock().unwrap().is_none());
    }

    #[test]
    fn authenticate_request_add_authentication_headers_to_request() {
        // Arrange
        let ok_response = create_ok_response();
        let sender = MockSender::new(vec![Ok(ok_response)]);
        let client = ApiClient::with_dependencies("https://example.com".to_string(), "test_client", sender, OsRng);
        let request_builder = client.client.get("https://example.com/endpoint");
        let payload = serde_json::to_vec(&json!({ "key": "value" })).unwrap();

        *client.session_key.lock().unwrap() = Some(SessionKey(vec![1; 32]));
        *client.session_token.lock().unwrap() = Some("test_token".to_string());

        // Act
        let result = client.authenticate_request("https://example.com/endpoint", "GET", Some(&payload), request_builder);

        // Assert that all required headers are present
        let request = result.unwrap().build().unwrap();
        let headers = request.headers();

        let auth = headers.get("Authorization").expect("Authorization header missing");
        assert_eq!(auth.to_str().unwrap(), "Bearer test_token");

        let client_id = headers.get("X-Client-ID").expect("X-Client-ID header missing");
        assert_eq!(client_id.to_str().unwrap(), "test_client");

        let timestamp = headers.get("X-Timestamp").expect("X-Timestamp header missing");
        assert!(timestamp.to_str().unwrap().parse::<u64>().is_ok(), "Timestamp should be numeric");

        let nonce = headers.get("X-Nonce").expect("X-Nonce header missing");
        assert_eq!(nonce.len(), 32, "Nonce should be 32 hex characters");
        assert!(nonce.to_str().unwrap().chars().all(|c| c.is_ascii_hexdigit()), "Nonce should be valid hex");

        let signature = headers.get("X-Signature").expect("X-Signature header missing");
        assert_eq!(signature.len(), 64, "Signature should be 64 hex characters (SHA256)");
        assert!(signature.to_str().unwrap().chars().all(|c| c.is_ascii_hexdigit()), "Signature should be valid hex");
        assert!(headers.get("X-Signature").is_some(), "X-Signature header missing");
    }

    #[test]
    fn authenticate_request_when_empty_payload_add_authentication_headers_to_request() {
        // Arrange
        let ok_response = create_ok_response();
        let sender = MockSender::new(vec![Ok(ok_response)]);
        let client = ApiClient::with_dependencies("https://example.com".to_string(), "test_client", sender, OsRng);
        let request_builder = client.client.get("https://example.com/endpoint");

        *client.session_key.lock().unwrap() = Some(SessionKey(vec![1; 32]));
        *client.session_token.lock().unwrap() = Some("test_token".to_string());

        // Act
        let result = client.authenticate_request("https://example.com/endpoint", "GET", None, request_builder);

        // Assert
        let request = result.unwrap().build().unwrap();
        let headers = request.headers();

        let signature = headers.get("X-Signature").expect("X-Signature header missing");
        assert_eq!(signature.len(), 64, "Signature should be 64 hex characters (SHA256)");
        assert!(signature.to_str().unwrap().chars().all(|c| c.is_ascii_hexdigit()), "Signature should be valid hex");
        assert!(headers.get("X-Signature").is_some(), "X-Signature header missing");
    }

    #[test]
    fn authenticate_request_generates_unique_nonces() {
        // Arrange
        let client = ApiClient::new("https://example.com".to_string(), "test_client");
        *client.session_key.lock().unwrap() = Some(SessionKey(vec![1; 32]));
        *client.session_token.lock().unwrap() = Some("test_token".to_string());

        // Act - call authenticate_request multiple times
        let request1 = client.client.get("https://example.com/endpoint");
        let result1 = client.authenticate_request("https://example.com/endpoint", "GET", None, request1).unwrap();
        let built1 = result1.build().unwrap();

        let request2 = client.client.get("https://example.com/endpoint");
        let result2 = client.authenticate_request("https://example.com/endpoint", "GET", None, request2).unwrap();
        let built2 = result2.build().unwrap();

        // Assert - nonces should be different
        let nonce1 = built1.headers().get("X-Nonce").unwrap().to_str().unwrap();
        let nonce2 = built2.headers().get("X-Nonce").unwrap().to_str().unwrap();
        assert_ne!(nonce1, nonce2, "Nonces should be unique across requests");

        let signature1 = built1.headers().get("X-Signature").unwrap().to_str().unwrap();
        let signature2 = built2.headers().get("X-Signature").unwrap().to_str().unwrap();
        assert_ne!(signature1, signature2, "Signatures should be different because of unique nonces");
    }

    #[test]
    fn authenticate_request_produces_same_signature_for_same_input() {
        // Arrange
        let rng1 = MockRngProvider::new(12345);
        let rng2 = MockRngProvider::new(12345);
        let client1 = ApiClient::with_dependencies("https://example.com".to_string(), "test_client", DefaultSender, rng1);
        let client2 = ApiClient::with_dependencies("https://example.com".to_string(), "test_client", DefaultSender, rng2);
        *client1.session_key.lock().unwrap() = Some(SessionKey(vec![1; 32]));
        *client1.session_token.lock().unwrap() = Some("test_token".to_string());
        *client2.session_key.lock().unwrap() = Some(SessionKey(vec![1; 32]));
        *client2.session_token.lock().unwrap() = Some("test_token".to_string());

        // Act - call authenticate_request multiple times
        let request1 = client1.client.get("https://example.com/endpoint");
        let result1 = client1.authenticate_request("https://example.com/endpoint", "GET", None, request1).unwrap();
        let built1 = result1.build().unwrap();

        let request2 = client2.client.get("https://example.com/endpoint");
        let result2 = client2.authenticate_request("https://example.com/endpoint", "GET", None, request2).unwrap();
        let built2 = result2.build().unwrap();

        // Assert - nonces should be different
        let signature1 = built1.headers().get("X-Signature").unwrap().to_str().unwrap();
        let signature2 = built2.headers().get("X-Signature").unwrap().to_str().unwrap();
        assert_eq!(signature1, signature2, "Signatures should be equal because of same nonce and inputs");
    }


    #[test]
    fn authenticate_request_produces_different_signatures_for_different_inputs() {
        let test_cases = vec![
            (
                "different paths",
                ("https://example.com/endpoint1", "GET", None::<&[u8]>, "test_client"),
                ("https://example.com/endpoint2", "GET", None::<&[u8]>, "test_client"),
            ),
            (
                "different methods",
                ("https://example.com/endpoint", "GET", None::<&[u8]>, "test_client"),
                ("https://example.com/endpoint", "POST", None::<&[u8]>, "test_client"),
            ),
            (
                "different payloads",
                ("https://example.com/endpoint", "POST", Some(b"payload1".as_slice()), "test_client"),
                ("https://example.com/endpoint", "POST", Some(b"payload2".as_slice()), "test_client"),
            ),
            (
                "different client IDs",
                ("https://example.com/endpoint", "GET", None::<&[u8]>, "client1"),
                ("https://example.com/endpoint", "GET", None::<&[u8]>, "client2"),
            ),
        ];

        for (test_name, case1, case2) in test_cases {
            // Arrange
            let rng1 = MockRngProvider::new(12345);
            let rng2 = MockRngProvider::new(12345);
            let (url1, method1, payload1, client_id1) = case1;
            let (url2, method2, payload2, client_id2) = case2;

            let client1 = ApiClient::with_dependencies("https://example.com".to_string(), client_id1, DefaultSender, rng1);
            let client2 = ApiClient::with_dependencies("https://example.com".to_string(), client_id2, DefaultSender, rng2);

            // Set up authentication for both clients
            *client1.session_key.lock().unwrap() = Some(SessionKey(vec![1; 32]));
            *client1.session_token.lock().unwrap() = Some("test_token".to_string());
            *client2.session_key.lock().unwrap() = Some(SessionKey(vec![1; 32]));
            *client2.session_token.lock().unwrap() = Some("test_token".to_string());

            // Act
            let request1 = match method1 {
                "GET" => client1.client.get(url1),
                "POST" => client1.client.post(url1),
                _ => panic!("Unsupported method: {}", method1),
            };
            let result1 = client1.authenticate_request(url1, method1, payload1, request1).unwrap();
            let built1 = result1.build().unwrap();

            let request2 = match method2 {
                "GET" => client2.client.get(url2),
                "POST" => client2.client.post(url2),
                _ => panic!("Unsupported method: {}", method2),
            };
            let result2 = client2.authenticate_request(url2, method2, payload2, request2).unwrap();
            let built2 = result2.build().unwrap();

            // Assert
            let signature1 = built1.headers().get("X-Signature").unwrap().to_str().unwrap();
            let signature2 = built2.headers().get("X-Signature").unwrap().to_str().unwrap();
            assert_ne!(
                signature1, signature2,
                "Signatures should be different for {}", test_name
            );
        }
    }


    #[tokio::test]
    async fn error_if_unsuccessful_returns_error_for_non_success_status() {
        // Arrange
        let response = create_error_response(StatusCode::BAD_REQUEST, "error message");

        // Act
        let result = error_if_unsuccessful(response).await;

        // Assert
        assert!(result.is_err());
        if let Err(Error::UnexpectedStatus { status, body }) = result {
            assert_eq!(status, 400);
            assert_eq!(body, "error message");
        } else {
            panic!("Expected Error::UnexpectedStatus");
        }
    }

    #[tokio::test]
    async fn error_if_unsuccessful_returns_ok_for_success_status() {
        // Arrange
        let response = create_ok_response();

        // Act
        let result = error_if_unsuccessful(response).await;

        // Assert
        assert!(result.is_ok());
    }


    #[test]
    fn is_authenticated_returns_false_when_session_key_is_none() {
        // Arrange
        let client = ApiClient::new("https://example.com".to_string(), "test_client");

        // Act
        let result = client.is_authenticated();

        // Assert
        assert!(!result);
    }

    #[test]
    fn is_authenticated_returns_true_when_session_key_is_some() {
        // Arrange
        let client = ApiClient::new("https://example.com".to_string(), "test_client");
        *client.session_key.lock().unwrap() = Some(SessionKey(vec![1, 2, 3]));

        // Act
        let result = client.is_authenticated();

        // Assert
        assert!(result);
    }

    #[tokio::test]
    async fn send_get_when_authenticated_sends_authenticated_request() {
        // Arrange
        let ok_response = create_ok_response();
        let sender = MockSender::new(vec![Ok(ok_response)]);
        let client = ApiClient::with_dependencies("https://example.com".to_string(), "test_client", sender, OsRng);

        // Set up authentication
        *client.session_key.lock().unwrap() = Some(SessionKey(vec![1; 32]));
        *client.session_token.lock().unwrap() = Some("test_token".to_string());

        // Act
        let result = client.send_get("https://example.com/endpoint").await;

        // Assert
        assert!(result.is_ok());

        // Verify request details
        let captured_requests = client.sender.get_captured_requests();
        assert_eq!(captured_requests.len(), 1);

        let request = &captured_requests[0];
        assert_eq!(request.method(), "GET");
        assert_eq!(request.url().as_str(), "https://example.com/endpoint");

        // Verify authentication headers
        let headers = request.headers();
        assert!(headers.get("Authorization").is_some());
        assert!(headers.get("X-Client-ID").is_some());
        assert!(headers.get("X-Timestamp").is_some());
        assert!(headers.get("X-Nonce").is_some());
        assert!(headers.get("X-Signature").is_some());
    }

    #[tokio::test]
    async fn send_get_when_unauthenticated_returns_unauthenticated_error() {
        // Arrange
        let sender = MockSender::new(vec![]);
        let client = ApiClient::with_dependencies("https://example.com".to_string(), "test_client", sender, OsRng);

        // Act
        let result = client.send_get("https://example.com/endpoint").await;

        // Assert
        assert!(result.is_err());
        match result {
            Err(Error::Unauthenticated) => {},
            _ => panic!("Expected Error::Unauthenticated"),
        }

        // Verify no requests were sent
        let captured_requests = client.sender.get_captured_requests();
        assert_eq!(captured_requests.len(), 0);
    }

    #[tokio::test]
    async fn send_get_when_response_has_error_status_returns_error() {
        // Arrange
        let error_response = create_error_response(StatusCode::BAD_REQUEST, "error message");
        let sender = MockSender::new(vec![Ok(error_response)]);
        let client = ApiClient::with_dependencies("https://example.com".to_string(), "test_client", sender, OsRng);

        // Set up authentication
        *client.session_key.lock().unwrap() = Some(SessionKey(vec![1; 32]));
        *client.session_token.lock().unwrap() = Some("test_token".to_string());

        // Act
        let result = client.send_get("https://example.com/endpoint").await;

        // Assert
        assert!(result.is_err());
        match result {
            Err(Error::UnexpectedStatus { status, body }) => {
                assert_eq!(status, 400);
                assert_eq!(body, "error message");
            },
            _ => panic!("Expected Error::UnexpectedStatus"),
        }
    }

    #[tokio::test]
    async fn send_post_json_when_authenticated_sends_authenticated_request_with_json_payload() {
        // Arrange
        let ok_response = create_ok_response();
        let sender = MockSender::new(vec![Ok(ok_response)]);
        let client = ApiClient::with_dependencies("https://example.com".to_string(), "test_client", sender, OsRng);

        // Set up authentication
        *client.session_key.lock().unwrap() = Some(SessionKey(vec![1; 32]));
        *client.session_token.lock().unwrap() = Some("test_token".to_string());

        let payload = json!({ "key": "value" });

        // Act
        let result = client.send_post_json("https://example.com/endpoint", &payload).await;

        // Assert
        assert!(result.is_ok());

        // Verify request details
        let captured_requests = client.sender.get_captured_requests();
        assert_eq!(captured_requests.len(), 1);

        let request = &captured_requests[0];
        assert_eq!(request.method(), "POST");
        assert_eq!(request.url().as_str(), "https://example.com/endpoint");

        // Verify content type
        let headers = request.headers();
        assert_eq!(headers.get("Content-Type").unwrap(), "application/json");

        // Verify authentication headers
        assert!(headers.get("Authorization").is_some());
        assert!(headers.get("X-Client-ID").is_some());
        assert!(headers.get("X-Timestamp").is_some());
        assert!(headers.get("X-Nonce").is_some());
        assert!(headers.get("X-Signature").is_some());
    }

    #[tokio::test]
    async fn send_post_json_when_unauthenticated_returns_unauthenticated_error() {
        // Arrange
        let sender = MockSender::new(vec![]);
        let client = ApiClient::with_dependencies("https://example.com".to_string(), "test_client", sender, OsRng);
        let payload = json!({ "key": "value" });

        // Act
        let result = client.send_post_json("https://example.com/endpoint", &payload).await;

        // Assert
        assert!(result.is_err());
        match result {
            Err(Error::Unauthenticated) => {},
            _ => panic!("Expected Error::Unauthenticated"),
        }

        // Verify no requests were sent
        let captured_requests = client.sender.get_captured_requests();
        assert_eq!(captured_requests.len(), 0);
    }

    #[tokio::test]
    async fn send_post_json_when_serialization_fails_returns_serialization_error() {
        // This test is a bit tricky since most types can be serialized
        // We'll use a mock that simulates a serialization error

        // Arrange
        let sender = MockSender::new(vec![]);
        let client = ApiClient::with_dependencies("https://example.com".to_string(), "test_client", sender, OsRng);

        // Set up authentication
        *client.session_key.lock().unwrap() = Some(SessionKey(vec![1; 32]));
        *client.session_token.lock().unwrap() = Some("test_token".to_string());

        // Create a struct that will fail to serialize
        struct UnserializableType;
        impl Serialize for UnserializableType {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("Simulated serialization error"))
            }
        }

        let payload = UnserializableType;

        // Act
        let result = client.send_post_json("https://example.com/endpoint", &payload).await;

        // Assert
        assert!(result.is_err());
        match result {
            Err(Error::Serialization(_)) => {},
            _ => panic!("Expected Error::Serialization"),
        }
    }

    #[tokio::test]
    async fn send_post_octet_stream_when_authenticated_sends_authenticated_request_with_binary_payload() {
        // Arrange
        let ok_response = create_ok_response();
        let sender = MockSender::new(vec![Ok(ok_response)]);
        let client = ApiClient::with_dependencies("https://example.com".to_string(), "test_client", sender, OsRng);

        // Set up authentication
        *client.session_key.lock().unwrap() = Some(SessionKey(vec![1; 32]));
        *client.session_token.lock().unwrap() = Some("test_token".to_string());

        let payload = vec![1, 2, 3, 4, 5];

        // Act
        let result = client.send_post_octet_stream("https://example.com/endpoint", payload.clone()).await;

        // Assert
        assert!(result.is_ok());

        // Verify request details
        let captured_requests = client.sender.get_captured_requests();
        assert_eq!(captured_requests.len(), 1);

        let request = &captured_requests[0];
        assert_eq!(request.method(), "POST");
        assert_eq!(request.url().as_str(), "https://example.com/endpoint");

        // Verify content type
        let headers = request.headers();
        assert_eq!(headers.get("Content-Type").unwrap(), "application/octet-stream");

        // Verify authentication headers
        assert!(headers.get("Authorization").is_some());
        assert!(headers.get("X-Client-ID").is_some());
        assert!(headers.get("X-Timestamp").is_some());
        assert!(headers.get("X-Nonce").is_some());
        assert!(headers.get("X-Signature").is_some());
    }

    #[tokio::test]
    async fn send_post_octet_stream_when_unauthenticated_returns_unauthenticated_error() {
        // Arrange
        let sender = MockSender::new(vec![]);
        let client = ApiClient::with_dependencies("https://example.com".to_string(), "test_client", sender, OsRng);
        let payload = vec![1, 2, 3, 4, 5];

        // Act
        let result = client.send_post_octet_stream("https://example.com/endpoint", payload).await;

        // Assert
        assert!(result.is_err());
        match result {
            Err(Error::Unauthenticated) => {},
            _ => panic!("Expected Error::Unauthenticated"),
        }

        // Verify no requests were sent
        let captured_requests = client.sender.get_captured_requests();
        assert_eq!(captured_requests.len(), 0);
    }
}
