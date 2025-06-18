use std::sync::Arc;
use http::StatusCode;
use reqwest::Response;
use crate::api::AuthApi;
use crate::api::mock_rng_provider::MockRngProvider;
use crate::api::mock_sender::{create_error_response, create_ok_response, MockSender};
use crate::{ApiClient, Error};
use crate::api::api_client::SessionKey;
use crate::crypto::ArgonCipher;

#[tokio::test]
async fn register_when_server_returns_error_returns_error() {
    // Arrange
    let client_id = "test_client";
    let password = "test_password";

    // Create an error response for the registration start
    let error_response = create_error_response(StatusCode::BAD_REQUEST, "Client ID already exists");

    let sender = MockSender::new(vec![
        Ok(error_response),
    ]);

    let rng = MockRngProvider::new(12345);

    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        client_id,
        sender,
        rng
    );

    // Act
    let auth_api: &dyn AuthApi = &client;
    let result = auth_api.register(client_id, password).await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::UnexpectedStatus { status, body }) => {
            assert_eq!(status, 400);
            assert_eq!(body, "Client ID already exists");
        },
        _ => panic!("Expected Error::UnexpectedStatus"),
    }

    assert!(!client.is_authenticated(), "Client should not be authenticated");

    // Verify the request that was sent
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 1);
    assert_eq!(captured_requests[0].url().path(), "/register/start");
}

#[tokio::test]
async fn login_when_server_returns_error_returns_error() {
    // Arrange
    let client_id = "test_client";
    let password = "test_password";

    // Create an error response for the login start
    let error_response = Response::from(
        http::response::Builder::new()
            .status(StatusCode::UNAUTHORIZED)
            .body("Invalid credentials".as_bytes().to_vec())
            .unwrap()
    );

    let sender = MockSender::new(vec![
        Ok(error_response),
    ]);

    let rng = MockRngProvider::new(12345);

    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        client_id,
        sender,
        rng
    );

    // Act
    let auth_api: &dyn AuthApi = &client;
    let result = auth_api.login(client_id, password).await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::UnexpectedStatus { status, body }) => {
            assert_eq!(status, 401);
            assert_eq!(body, "Invalid credentials");
        },
        _ => panic!("Expected Error::UnexpectedStatus"),
    }

    assert!(!client.is_authenticated(), "Client should not be authenticated");

    // Verify the request that was sent
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 1);
    assert_eq!(captured_requests[0].url().path(), "/login/start");
}

#[tokio::test]
async fn logout_when_authenticated_clears_session_data() {
    // Arrange
    let client_id = "test_client";

    // Create a mock response for the logout request
    let logout_response = create_ok_response();

    let sender = MockSender::new(vec![
        Ok(logout_response),
    ]);

    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        client_id,
        sender,
        MockRngProvider::new(12345)
    );

    // Set up authentication state
    *client.session_key.lock().unwrap() = Some(SessionKey(vec![1; 32]));
    *client.session_token.lock().unwrap() = Some("test_token".to_string());
    let cipher = Arc::new(ArgonCipher::new("test_password").unwrap());
    *client.cipher.lock().unwrap() = Some(cipher);

    // Act
    let result = client.logout().await;

    // Assert
    assert!(result.is_ok(), "Logout should succeed");
    assert!(!client.is_authenticated(), "Client should no longer be authenticated");
    assert!(client.session_token.lock().unwrap().is_none(), "Session token should be cleared");
    assert!(client.session_key.lock().unwrap().is_none(), "Session key should be cleared");
    assert!(client.cipher.lock().unwrap().is_none(), "Cipher should be cleared");

    // Verify the request that was sent
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 1);
    assert_eq!(captured_requests[0].url().path(), "/logout");
    assert_eq!(captured_requests[0].method(), "POST");
}

#[tokio::test]
async fn logout_when_unauthenticated_returns_error() {
    // Arrange
    let client_id = "test_client";

    let sender = MockSender::new(vec![]);

    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        client_id,
        sender,
        MockRngProvider::new(12345)
    );

    // Act
    let result = client.logout().await;

    // Assert
    assert!(result.is_err());
    match result {
        Err(Error::Unauthenticated) => {},
        _ => panic!("Expected Error::Unauthenticated"),
    }

    // Verify that no requests were sent
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 0);
}