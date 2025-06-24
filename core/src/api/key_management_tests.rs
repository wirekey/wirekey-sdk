use crate::api::error::Error;
use crate::api::key_management::KeyManagementApi;
use crate::api::mock_rng_provider::MockRngProvider;
use crate::api::mock_sender::{MockSender};
use crate::api::prekey_bundle::{PreKeyBundle, PublicOneTimePreKey, PublicSignedPreKey};
use crate::api::private_keys::{PrivateKeys, PrivateOneTimePreKey, PrivateSignedPreKey};
use crate::api::responses::PrekeyCountResponse;
use crate::crypto::ArgonCipher;
use crate::ApiClient;
use http::StatusCode;
use reqwest::Response;
use std::sync::Arc;
use crate::api::test_utils::{create_error_response, create_ok_response, create_ok_response_with_payload};

fn test_prekey_bundle() -> PreKeyBundle {
    PreKeyBundle {
        identity_key: [1; 32],
        signed_prekey: PublicSignedPreKey {
            id: 1,
            created_at: 123456789,
            public_key: [2; 32],
            signature: [3; 64],
        },
        one_time_prekey: Some(PublicOneTimePreKey {
            id: 2,
            created_at: 123456789,
            public_key: [4; 32],
        }),
    }
}

fn test_private_keys() -> PrivateKeys {
    PrivateKeys {
        identity_private_key: [1; 32],
        signed_prekeys: vec![
            PrivateSignedPreKey {
                id: 1,
                created_at: 123456789,
                private_key: [2; 32],
                signature: [3; 64],
            },
        ],
        one_time_prekeys: vec![
            PrivateOneTimePreKey {
                id: 2,
                created_at: 123456789,
                private_key: [4; 32],
            },
        ],
    }
}

#[tokio::test]
async fn get_prekey_bundle_when_successful_returns_prekey_bundle() {
    // Arrange
    let prekey_bundle = test_prekey_bundle();
    let payload = serde_json::to_vec(&prekey_bundle).unwrap();
    let response = create_ok_response_with_payload(payload);
    let sender = MockSender::new(vec![Ok(response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Set up authentication
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());

    // Act
    let result = client.get_prekey_bundle("target_client").await;

    // Assert
    assert!(result.is_ok(), "Should return Ok result");
    let bundle = result.unwrap();
    assert_eq!(bundle.identity_key, [1; 32]);
    assert_eq!(bundle.signed_prekey.id, 1);
    assert_eq!(bundle.signed_prekey.public_key, [2; 32]);
    assert_eq!(bundle.signed_prekey.signature, [3; 64]);
    assert!(bundle.one_time_prekey.is_some());
    let prekey = bundle.one_time_prekey.unwrap();
    assert_eq!(prekey.id, 2);
    assert_eq!(prekey.public_key, [4; 32]);

    // Verify request details
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 1);
    let request = &captured_requests[0];
    assert_eq!(request.method(), "GET");
    assert_eq!(request.url().as_str(), "https://example.com/prekey-bundle/target_client");
}

#[tokio::test]
async fn get_prekey_bundle_when_unauthenticated_returns_error() {
    // Arrange
    let sender = MockSender::new(vec![]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Act
    let result = client.get_prekey_bundle("target_client").await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::Unauthenticated) => {},
        _ => panic!("Expected Error::Unauthenticated"),
    }
}

#[tokio::test]
async fn get_prekey_bundle_when_server_error_returns_error() {
    // Arrange
    let error_response = create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Server error");
    let sender = MockSender::new(vec![Ok(error_response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Set up authentication
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());

    // Act
    let result = client.get_prekey_bundle("target_client").await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::UnexpectedStatus { status, body }) => {
            assert_eq!(status, 500);
            assert_eq!(body, "Server error");
        },
        _ => panic!("Expected Error::UnexpectedStatus"),
    }
}

#[tokio::test]
async fn get_prekey_bundle_when_invalid_json_returns_error() {
    // Arrange
    let response = create_ok_response_with_payload("invalid json".as_bytes().to_vec());
    let sender = MockSender::new(vec![Ok(response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Set up authentication
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());

    // Act
    let result = client.get_prekey_bundle("target_client").await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::Deserialization(_)) => {},
        _ => panic!("Expected Error::Deserialization"),
    }
}

#[tokio::test]
async fn upload_prekey_bundle_when_successful_returns_ok() {
    // Arrange
    let ok_response = create_ok_response();
    let sender = MockSender::new(vec![Ok(ok_response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Set up authentication
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());

    let prekey_bundle = test_prekey_bundle();

    // Act
    let result = client.upload_prekey_bundle(&prekey_bundle).await;

    // Assert
    assert!(result.is_ok());

    // Verify request details
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 1);
    let request = &captured_requests[0];
    assert_eq!(request.method(), "POST");
    assert_eq!(request.url().as_str(), "https://example.com/prekey-bundle");
    assert_eq!(request.headers().get("Content-Type").unwrap(), "application/json");
}

#[tokio::test]
async fn upload_prekey_bundle_when_unauthenticated_returns_error() {
    // Arrange
    let sender = MockSender::new(vec![]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    let prekey_bundle = test_prekey_bundle();

    // Act
    let result = client.upload_prekey_bundle(&prekey_bundle).await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::Unauthenticated) => {},
        _ => panic!("Expected Error::Unauthenticated"),
    }
}

#[tokio::test]
async fn upload_prekey_bundle_when_server_error_returns_error() {
    // Arrange
    let error_response = create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Server error");
    let sender = MockSender::new(vec![Ok(error_response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Set up authentication
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());

    let prekey_bundle = test_prekey_bundle();

    // Act
    let result = client.upload_prekey_bundle(&prekey_bundle).await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::UnexpectedStatus { status, body }) => {
            assert_eq!(status, 500);
            assert_eq!(body, "Server error");
        },
        _ => panic!("Expected Error::UnexpectedStatus"),
    }
}

#[tokio::test]
async fn get_prekey_count_when_successful_returns_count() {
    // Arrange
    let count_response = PrekeyCountResponse { count: 42 };
    let payload = serde_json::to_vec(&count_response).unwrap();
    let response = create_ok_response_with_payload(payload);
    let sender = MockSender::new(vec![Ok(response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Set up authentication
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());

    // Act
    let result = client.get_prekey_count().await;

    // Assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);

    // Verify request details
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 1);
    let request = &captured_requests[0];
    assert_eq!(request.method(), "GET");
    assert_eq!(request.url().as_str(), "https://example.com/prekey-count");
}

#[tokio::test]
async fn get_prekey_count_when_unauthenticated_returns_error() {
    // Arrange
    let sender = MockSender::new(vec![]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Act
    let result = client.get_prekey_count().await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::Unauthenticated) => {},
        _ => panic!("Expected Error::Unauthenticated"),
    }
}

#[tokio::test]
async fn get_prekey_count_when_server_error_returns_error() {
    // Arrange
    let error_response = create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Server error");
    let sender = MockSender::new(vec![Ok(error_response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Set up authentication
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());

    // Act
    let result = client.get_prekey_count().await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::UnexpectedStatus { status, body }) => {
            assert_eq!(status, 500);
            assert_eq!(body, "Server error");
        },
        _ => panic!("Expected Error::UnexpectedStatus"),
    }
}

#[tokio::test]
async fn get_prekey_count_when_invalid_json_returns_error() {
    // Arrange
    let response = create_ok_response_with_payload("invalid json".as_bytes().to_vec());
    let sender = MockSender::new(vec![Ok(response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Set up authentication
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());

    // Act
    let result = client.get_prekey_count().await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::Deserialization(_)) => {},
        _ => panic!("Expected Error::Deserialization"),
    }
}

#[tokio::test]
async fn get_private_keys_when_successful_returns_private_keys() {
    // Arrange
    let private_keys = test_private_keys();
    let cipher = ArgonCipher::new("test_secret").unwrap();
    let serialized = serde_json::to_vec(&private_keys).unwrap();
    let encrypted = cipher.encrypt(&serialized).unwrap();

    let response = create_ok_response_with_payload(encrypted);
    let sender = MockSender::new(vec![Ok(response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Set up authentication
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());
    *client.cipher.lock().unwrap() = Some(Arc::new(cipher));

    // Act
    let result = client.get_private_keys().await;

    // Assert
    assert!(result.is_ok(), "Should return Ok result");
    let keys = result.unwrap();
    assert_eq!(keys.identity_private_key, [1; 32]);
    assert_eq!(keys.signed_prekeys.len(), 1);
    assert_eq!(keys.signed_prekeys[0].id, 1);
    assert_eq!(keys.signed_prekeys[0].private_key, [2; 32]);
    assert_eq!(keys.signed_prekeys[0].signature, [3; 64]);
    assert_eq!(keys.one_time_prekeys.len(), 1);
    assert_eq!(keys.one_time_prekeys[0].id, 2);
    assert_eq!(keys.one_time_prekeys[0].private_key, [4; 32]);

    // Verify request details
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 1);
    let request = &captured_requests[0];
    assert_eq!(request.method(), "GET");
    assert_eq!(request.url().as_str(), "https://example.com/private-keys");
}

#[tokio::test]
async fn get_private_keys_when_server_error_returns_error() {
    // Arrange
    let error_response = create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Server error");
    let sender = MockSender::new(vec![Ok(error_response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Set up authentication
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());
    *client.cipher.lock().unwrap() = Some(Arc::new(ArgonCipher::new("test_secret").unwrap()));

    // Act
    let result = client.get_private_keys().await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::UnexpectedStatus { status, body }) => {
            assert_eq!(status, 500);
            assert_eq!(body, "Server error");
        },
        _ => panic!("Expected Error::UnexpectedStatus"),
    }
}

#[tokio::test]
async fn get_private_keys_when_invalid_response_content_returns_error() {
    // Arrange
    let cipher = ArgonCipher::new("test_secret").unwrap();
    let payload = cipher.encrypt(&"invalid payload".as_bytes().to_vec()).unwrap();
    let response = create_ok_response_with_payload(payload);
    let sender = MockSender::new(vec![Ok(response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Set up authentication
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());
    *client.cipher.lock().unwrap() = Some(Arc::new(cipher));

    // Act
    let result = client.get_private_keys().await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::Deserialization(_)) => {},
        _ => panic!("Expected Error::Deserialization"),
    }
}

#[tokio::test]
async fn get_private_keys_when_unauthenticated_returns_error() {
    // Arrange
    let sender = MockSender::new(vec![]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Act
    let result = client.get_private_keys().await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::Unauthenticated) => {},
        _ => panic!("Expected Error::Unauthenticated"),
    }
}

#[tokio::test]
async fn get_private_keys_when_cipher_not_set_returns_error() {
    // Arrange
    let response = Response::from(
        http::response::Builder::new()
            .status(StatusCode::OK)
            .body(vec![1, 2, 3, 4])
            .unwrap()
    );

    let sender = MockSender::new(vec![Ok(response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Set up authentication but not cipher
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());

    // Act
    let result = client.get_private_keys().await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::Unauthenticated) => {},
        _ => panic!("Expected Error::Unauthenticated"),
    }
}

#[tokio::test]
async fn upload_private_keys_when_successful_returns_ok() {
    // Arrange
    let ok_response = create_ok_response();
    let sender = MockSender::new(vec![Ok(ok_response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Create a cipher for encryption/decryption
    let cipher = ArgonCipher::new("test_secret").unwrap();

    // Set up authentication
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());
    *client.cipher.lock().unwrap() = Some(Arc::new(cipher));

    let private_keys = test_private_keys();

    // Act
    let result = client.upload_private_keys(&private_keys).await;

    // Assert
    assert!(result.is_ok());

    // Verify request details
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 1);
    let request = &captured_requests[0];
    assert_eq!(request.method(), "POST");
    assert_eq!(request.url().as_str(), "https://example.com/private-keys");
    assert_eq!(request.headers().get("Content-Type").unwrap(), "application/octet-stream");
}

#[tokio::test]
async fn upload_private_keys_encrypts_payload_before_sending() {
    // Arrange
    let ok_response = create_ok_response();
    let sender = MockSender::new(vec![Ok(ok_response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    let cipher = ArgonCipher::new("test_secret").unwrap();

    // Set up authentication
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());
    *client.cipher.lock().unwrap() = Some(Arc::new(cipher));

    let private_keys = test_private_keys();

    let expected_identity_key = private_keys.identity_private_key;
    let expected_signed_prekey_count = private_keys.signed_prekeys.len();
    let expected_one_time_prekey_count = private_keys.one_time_prekeys.len();

    // Act
    let result = client.upload_private_keys(&private_keys).await;

    // Assert
    assert!(result.is_ok());
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 1);
    let request = &captured_requests[0];
    let body = request.body().unwrap().as_bytes().unwrap();

    // Verify it's NOT plain JSON by trying to deserialize directly
    let json_parse_result = serde_json::from_slice::<PrivateKeys>(body);
    assert!(json_parse_result.is_err(), "Payload should be encrypted, not plain JSON");

    // Verify it IS encrypted by decrypting it successfully
    // Create a new cipher with the same secret for decryption
    let decrypt_cipher = ArgonCipher::new("test_secret").unwrap();
    let decrypted = decrypt_cipher.decrypt(body).expect("Should be able to decrypt the payload");
    let decrypted_private_keys: PrivateKeys = serde_json::from_slice(&decrypted)
        .expect("Decrypted payload should be valid PrivateKeys JSON");

    // Verify the decrypted content matches what we sent
    assert_eq!(decrypted_private_keys.identity_private_key, expected_identity_key);
    assert_eq!(decrypted_private_keys.signed_prekeys.len(), expected_signed_prekey_count);
    assert_eq!(decrypted_private_keys.one_time_prekeys.len(), expected_one_time_prekey_count);
}


#[tokio::test]
async fn upload_private_keys_when_unauthenticated_returns_error() {
    // Arrange
    let sender = MockSender::new(vec![]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    let private_keys = PrivateKeys {
        identity_private_key: [1; 32],
        signed_prekeys: vec![],
        one_time_prekeys: vec![],
    };

    // Act
    let result = client.upload_private_keys(&private_keys).await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::Unauthenticated) => {},
        _ => panic!("Expected Error::Unauthenticated"),
    }
}

#[tokio::test]
async fn upload_private_keys_when_cipher_not_set_returns_error() {
    // Arrange
    let sender = MockSender::new(vec![]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Set up authentication but not cipher
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());

    let private_keys = PrivateKeys {
        identity_private_key: [1; 32],
        signed_prekeys: vec![],
        one_time_prekeys: vec![],
    };

    // Act
    let result = client.upload_private_keys(&private_keys).await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::Unauthenticated) => {},
        _ => panic!("Expected Error::Unauthenticated"),
    }
}

#[tokio::test]
async fn upload_private_keys_when_server_error_returns_error() {
    // Arrange
    let error_response = create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Server error");
    let sender = MockSender::new(vec![Ok(error_response)]);
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Create a cipher for encryption/decryption
    let cipher = ArgonCipher::new("test_secret").unwrap();

    // Set up authentication
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());
    *client.cipher.lock().unwrap() = Some(Arc::new(cipher));

    let private_keys = PrivateKeys {
        identity_private_key: [1; 32],
        signed_prekeys: vec![],
        one_time_prekeys: vec![],
    };

    // Act
    let result = client.upload_private_keys(&private_keys).await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::UnexpectedStatus { status, body }) => {
            assert_eq!(status, 500);
            assert_eq!(body, "Server error");
        },
        _ => panic!("Expected Error::UnexpectedStatus"),
    }
}
