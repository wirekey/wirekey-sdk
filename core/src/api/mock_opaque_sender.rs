use std::sync::{Arc, Mutex};
use aes_gcm::aead::OsRng;
use async_trait::async_trait;
use http::StatusCode;
use opaque_ke::{CredentialRequest, Identifiers, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup};
use reqwest::{Request, RequestBuilder, Response};
use crate::api::auth::SERVER_ID;
use crate::api::http_sender::HttpSender;
use crate::api::test_utils::{create_error_response, create_ok_response, create_ok_response_with_payload};
use crate::ApiClient;

pub struct MockOpaqueSender {
    server_setup: ServerSetup<ApiClient>,
    password_file: Arc<Mutex<Option<ServerRegistration<ApiClient>>>>,
    pub captured_requests: Arc<Mutex<Vec<Request>>>,
    // Error configurations for different authentication steps
    login_error: Arc<Mutex<Option<(StatusCode, String)>>>,
    register_start_error: Arc<Mutex<Option<(StatusCode, String)>>>,
    register_finish_error: Arc<Mutex<Option<(StatusCode, String)>>>,
    logout_error: Arc<Mutex<Option<(StatusCode, String)>>>,
}

impl MockOpaqueSender {
    pub fn new() -> Self {
        let mut rng = OsRng;
        Self{
            server_setup: ServerSetup::<ApiClient>::new(&mut rng),
            password_file: Arc::new(Mutex::new(None)),
            captured_requests: Arc::new(Mutex::new(Vec::new())),
            login_error: Arc::new(Mutex::new(None)),
            register_start_error: Arc::new(Mutex::new(None)),
            register_finish_error: Arc::new(Mutex::new(None)),
            logout_error: Arc::new(Mutex::new(None)),
        }
    }

    pub fn get_captured_requests(&self) -> std::sync::MutexGuard<'_, Vec<Request>> {
        self.captured_requests.lock().unwrap()
    }

    // Methods to configure error responses
    pub fn set_login_error(&self, status: StatusCode, message: &str) {
        *self.login_error.lock().unwrap() = Some((status, message.to_string()));
    }

    pub fn set_register_start_error(&self, status: StatusCode, message: &str) {
        *self.register_start_error.lock().unwrap() = Some((status, message.to_string()));
    }

    pub fn set_register_finish_error(&self, status: StatusCode, message: &str) {
        *self.register_finish_error.lock().unwrap() = Some((status, message.to_string()));
    }

    pub fn set_logout_error(&self, status: StatusCode, message: &str) {
        *self.logout_error.lock().unwrap() = Some((status, message.to_string()));
    }

    // Clear all configured errors
    pub fn clear_errors(&self) {
        *self.login_error.lock().unwrap() = None;
        *self.register_start_error.lock().unwrap() = None;
        *self.register_finish_error.lock().unwrap() = None;
        *self.logout_error.lock().unwrap() = None;
    }
}

fn extract_client_id_from_path(path: &str) -> String {
    // Extract client ID from paths like "/register/start/client123" or "/login/client123"
    path.split('/').last().expect("Path is empty").to_string()
}

#[async_trait]
impl HttpSender for MockOpaqueSender {
    async fn send(&self, request: RequestBuilder) -> Result<Response, reqwest::Error> {
        let built_request = request.build()?;
        self.captured_requests.lock().unwrap().push(built_request.try_clone().unwrap());

        let path = built_request.url().path();
        match path {
            p if p.starts_with("/register/start/") => {
                // Check if a register start error is configured
                if let Some((status, message)) = &*self.register_start_error.lock().unwrap() {
                    return Ok(create_error_response(*status, message));
                }

                let request_payload = built_request.body().unwrap().as_bytes().unwrap();
                let client_message = RegistrationRequest::<ApiClient>::deserialize(request_payload).unwrap();
                let user_id = extract_client_id_from_path(p);

                let server_register_start_result = ServerRegistration::<ApiClient>::start(
                    &self.server_setup,
                    client_message,
                    user_id.as_bytes(),
                ).unwrap();

                let response_payload = server_register_start_result.message.serialize();
                Ok(create_ok_response_with_payload(response_payload.to_vec()))
            }
            p if p.starts_with("/register/finish/") => {
                // Check if a register finish error is configured
                if let Some((status, message)) = &*self.register_finish_error.lock().unwrap() {
                    return Ok(create_error_response(*status, message));
                }

                let request_payload = built_request.body().unwrap().as_bytes().unwrap();
                let client_message = RegistrationUpload::<ApiClient>::deserialize(request_payload).unwrap();
                let password_file = ServerRegistration::<ApiClient>::finish(
                    client_message,
                );

                let mut password_file_guard = self.password_file.lock().unwrap();
                *password_file_guard = Some(password_file);

                Ok(create_ok_response())
            }
            p if p.starts_with("/login/") => {
                // Check if a login error is configured
                if let Some((status, message)) = &*self.login_error.lock().unwrap() {
                    return Ok(create_error_response(*status, message));
                }

                let request_payload = built_request.body().unwrap().as_bytes().unwrap();
                let client_message = CredentialRequest::<ApiClient>::deserialize(&request_payload).unwrap();
                let password_file = self.password_file.lock().unwrap().clone();

                if password_file.is_none() {
                    // Return 401 if user is not registered
                    return Ok(create_error_response(StatusCode::UNAUTHORIZED, "User not registered"));
                }

                let user_id = extract_client_id_from_path(p);
                let server_login_start_result = ServerLogin::start(
                    &mut OsRng,
                    &self.server_setup,
                    password_file,
                    client_message,
                    user_id.as_bytes(),
                    ServerLoginStartParameters {
                        context: None,
                        identifiers: Identifiers {
                            client: Some(user_id.as_bytes()),
                            server: Some(SERVER_ID),
                        },
                    },
                ).unwrap();
                let credential_response = server_login_start_result.message.serialize();

                let session_token = "mock_session_token_12345";
                let session_token_bytes = session_token.as_bytes();
                let session_token_len = session_token_bytes.len() as u8;

                let mut response_payload = Vec::new();
                response_payload.push(session_token_len);
                response_payload.extend_from_slice(session_token_bytes);
                response_payload.extend_from_slice(&credential_response);

                Ok(create_ok_response_with_payload(response_payload))
            }
            "/logout" => {
                // Check if a logout error is configured
                if let Some((status, message)) = &*self.logout_error.lock().unwrap() {
                    return Ok(create_error_response(*status, message));
                }

                Ok(create_ok_response())
            }
            _ => {
                panic!("Unexpected path: {}", path);
            }
        }
    }
}
