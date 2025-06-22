use crate::api::http_sender::HttpSender;
use async_trait::async_trait;
use reqwest::{Request, RequestBuilder, Response};
use std::sync::{Arc, Mutex};

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
impl HttpSender for MockSender {
    async fn send(&self, request: RequestBuilder) -> Result<Response, reqwest::Error> {
        // Build the request to capture it
        let built_request = request.build()?;
        self.captured_requests.lock().unwrap().push(built_request.try_clone().unwrap());

        // Return the mocked response
        self.responses.lock().unwrap().remove(0)
    }
}