use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct PrekeyCountResponse {
    pub count: u32,
}

#[derive(Deserialize)]
pub(super) struct LoginFinishResponse {
    pub session_token: String,
}
