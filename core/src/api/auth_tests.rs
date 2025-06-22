use crate::api::auth::AuthApi;
use crate::api::mock_opaque_sender::MockOpaqueSender;
use crate::api::mock_rng_provider::MockRngProvider;
use crate::{ApiClient, Error};
use http::StatusCode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

#[tokio::test]
async fn authenticate_when_login_successful_returns_ok() {
    // Arrange
    let sender = MockOpaqueSender::new();
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Pre-register the user to simulate an existing registered user
    client.authenticate("alice", "password123").await
        .expect("Initial registration should succeed");

    // Clear captured requests from registration
    client.sender.get_captured_requests().clear();

    // Act - authenticate again (this time should only login)
    client.authenticate("alice", "password123").await
        .expect("Authentication should succeed");

    // Assert
    assert!(client.is_authenticated(), "Client should be authenticated after successful login");

    // Verify request details - should be only 1 login request this time
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 1, "Should have sent one request");
    let request = &captured_requests[0];
    assert_eq!(request.method(), "POST", "Request method should be POST");
    assert!(request.url().path().starts_with("/login/"), "Request URL should start with /login/");
}

#[tokio::test]
async fn authenticate_when_login_fails_with_401_registers_and_logs_in() {
    // Arrange
    let sender = MockOpaqueSender::new();
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // We need to simulate a 401 response for the first login attempt
    // This is handled by the MockOpaqueSender when the password file is None

    // Act
    client.authenticate("bob", "password456").await
        .expect("Authentication should succeed after registration");

    // Assert
    assert!(client.is_authenticated(), "Client should be authenticated after successful login");

    // Verify request details - should have 4 requests: login (fails), register start, register finish, login (succeeds)
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 4, "Should have sent four requests");

    // First request should be login attempt
    let login_request = &captured_requests[0];
    assert_eq!(login_request.method(), "POST", "First request method should be POST");
    assert!(login_request.url().path().starts_with("/login/"), "First request URL should start with /login/");

    // Second request should be register start
    let register_start_request = &captured_requests[1];
    assert_eq!(register_start_request.method(), "POST", "Second request method should be POST");
    assert!(register_start_request.url().path().starts_with("/register/start/"), 
            "Second request URL should start with /register/start/");

    // Third request should be register finish
    let register_finish_request = &captured_requests[2];
    assert_eq!(register_finish_request.method(), "POST", "Third request method should be POST");
    assert!(register_finish_request.url().path().starts_with("/register/finish/"), 
            "Third request URL should start with /register/finish/");

    let login_request = &captured_requests[3];
    assert_eq!(login_request.method(), "POST", "Fourth request method should be POST");
    assert!(login_request.url().path().starts_with("/login/"), "Fourth request URL should start with /login/");
}

#[tokio::test]
async fn authenticate_with_empty_username_returns_error() {
    // Arrange
    let sender = MockOpaqueSender::new();
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Act
    let result = client.authenticate("", "password123").await;

    // Assert
    assert!(result.is_err(), "Authentication with empty username should fail");
}

#[tokio::test]
async fn authenticate_with_empty_password_returns_error() {
    // Arrange
    let sender = MockOpaqueSender::new();
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Act
    let result = client.authenticate("alice", "").await;

    // Assert
    assert!(result.is_err(), "Authentication with empty password should fail");
}

#[tokio::test]
async fn authenticate_when_server_returns_error_returns_error() {
    // Arrange
    let sender = MockOpaqueSender::new();
    // Configure the sender to return an error for login requests
    sender.set_login_error(StatusCode::INTERNAL_SERVER_ERROR, "Server error");

    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Act
    let result = client.authenticate("alice", "password123").await;

    // Assert
    assert!(result.is_err(), "Authentication should fail");

    // Verify the error type
    match result {
        Err(Error::UnexpectedStatus { status, body }) => {
            assert_eq!(status, 500, "Status code should be 500");
            assert_eq!(body, "Server error", "Error message should match");
        },
        _ => panic!("Expected Error::UnexpectedStatus"),
    }

    // Verify request details
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 1, "Should have sent one request");
    let request = &captured_requests[0];
    assert_eq!(request.method(), "POST", "Request method should be POST");
}

#[tokio::test]
async fn logout_when_not_authenticated_returns_ok() {
    // Arrange
    let sender = MockOpaqueSender::new();
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Verify client is not authenticated
    assert!(!client.is_authenticated(), "Client should not be authenticated initially");

    // Act
    client.logout().await.expect("Logout should succeed even when not authenticated");

    // Assert
    assert!(!client.is_authenticated(), "Client should still not be authenticated after logout");

    // Verify request details
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 0, "Should have sent any request");
}

#[tokio::test]
async fn logout_when_authenticated_clears_session_data() {
    // Arrange
    let sender = MockOpaqueSender::new();
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // First authenticate to set up session data
    let auth_result = client.authenticate("alice", "password123").await;
    assert!(auth_result.is_ok(), "Authentication should succeed");
    assert!(client.is_authenticated(), "Client should be authenticated");

    // Act
    client.logout().await.expect("Logout should succeed");

    // Assert
    assert!(!client.is_authenticated(), "Client should not be authenticated after logout");

    // Verify request details
    let captured_requests = client.sender.get_captured_requests();
    assert!(captured_requests.len() > 1, "Should have sent multiple requests");
    let logout_request = captured_requests.last().unwrap();
    assert_eq!(logout_request.method(), "POST", "Logout request method should be POST");
    assert_eq!(logout_request.url().path(), "/logout", "Logout request URL should be /logout");
}

#[tokio::test]
async fn logout_when_server_returns_error_returns_error() {
    // Arrange
    // Create a sender that will return an error for logout requests
    let sender = MockOpaqueSender::new();
    sender.set_logout_error(StatusCode::INTERNAL_SERVER_ERROR, "Server error");

    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    // Set up authentication state manually
    *client.session_token.lock().unwrap() = Some("test_token".to_string());
    *client.session_key.lock().unwrap() = Some(crate::api::api_client::SessionKey(vec![1; 32]));

    // Act
    let result = client.logout().await;

    // Assert
    assert!(result.is_err(), "Logout should fail");

    // Verify the error type
    match result {
        Err(Error::UnexpectedStatus { status, body }) => {
            assert_eq!(status, 500, "Status code should be 500");
            assert_eq!(body, "Server error", "Error message should match");
        },
        _ => panic!("Expected Error::UnexpectedStatus"),
    }

    // Verify request details
    let captured_requests = client.sender.get_captured_requests();
    assert_eq!(captured_requests.len(), 1, "Should have sent one request");
    let request = &captured_requests[0];
    assert_eq!(request.method(), "POST", "Request method should be POST");
    assert_eq!(request.url().path(), "/logout", "Request URL should be /logout");
}

#[tokio::test]
async fn authenticate_uses_anonymized_username_as_user_identifier() {
    // Arrange
    let sender = MockOpaqueSender::new();
    let client = ApiClient::with_dependencies(
        "https://example.com".to_string(),
        "test_client",
        sender,
        MockRngProvider::new(12345),
    );

    let username = "alice";
    let password = "password123";

    // Act
    client.authenticate(username, password).await
        .expect("Authentication should succeed");

    // Assert
    // Verify that the anonymized username was used in the request
    let captured_requests = client.sender.get_captured_requests();
    assert!(!captured_requests.is_empty(), "Should have captured at least one request");

    // Get the login request URL
    let login_request = &captured_requests[0];
    let url_path = login_request.url().path();
    assert!(url_path.starts_with("/login/"), "First request should be a login request");

    // Extract the user ID from the URL path
    let user_id = url_path.strip_prefix("/login/").unwrap();

    // The user ID should not be the original username
    assert_ne!(user_id, username, 
        "The request should use an anonymized username, not the original username");

    // The user ID should be a base64 encoded string (anonymized username)
    assert!(URL_SAFE_NO_PAD.decode(user_id).is_ok(),
        "The user ID should be a valid base64 encoded string (anonymized username)");
}
