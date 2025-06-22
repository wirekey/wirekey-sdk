use http::StatusCode;
use reqwest::Response;

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