use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use http::StatusCode;
use reqwest::{Request, RequestBuilder, Response};
use crate::api::http_send::HttpSend;

// Thread-safe mock that captures requests for inspection
pub(super) struct MockSender {
    pub responses: Arc<Mutex<Vec<Result<Response, reqwest::Error>>>>,
    pub captured_requests: Arc<Mutex<Vec<Request>>>,
}

impl MockSender {
    pub fn new(responses: Vec<Result<Response, reqwest::Error>>) -> Self {
        Self {
            responses: Arc::new(Mutex::new(responses)),
            captured_requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn get_captured_requests(&self) -> std::sync::MutexGuard<'_, Vec<Request>> {
        self.captured_requests.lock().unwrap()
    }
}

#[async_trait]
impl HttpSend for MockSender {
    async fn send(&self, request: RequestBuilder) -> Result<Response, reqwest::Error> {
        // Build the request to capture it
        let built_request = request.build()?;
        self.captured_requests.lock().unwrap().push(built_request.try_clone().unwrap());

        // Return the mocked response
        self.responses.lock().unwrap().remove(0)
    }
}

// Helper function to create a successful response
pub(super) fn create_ok_response() -> Response {
    create_ok_response_with_payload(Vec::new())
}

pub(super) fn create_ok_response_with_payload(payload: Vec<u8>) -> Response {
    Response::from(
        http::response::Builder::new()
            .status(StatusCode::OK)
            .body(payload)
            .unwrap()
    )
}

// Helper function to create an error response
pub(super) fn create_error_response(status: StatusCode, body: &str) -> Response {
    Response::from(
        http::response::Builder::new()
            .status(status)
            .body(body.as_bytes().to_vec())
            .unwrap()
    )
}