use async_trait::async_trait;
use reqwest::{RequestBuilder, Response};

#[async_trait]
pub trait HttpSend: Send + Sync {
    async fn send(&self, request: RequestBuilder) -> Result<Response, reqwest::Error>;
}

pub struct DefaultSender;

#[async_trait]
impl HttpSend for DefaultSender {
    async fn send(&self, request: RequestBuilder) -> Result<Response, reqwest::Error> {
        request.send().await
    }
}