use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(super) struct PrekeyCountResponse {
    pub count: u32,
}

#[derive(Serialize, Deserialize)]
pub(super) struct LoginFinishResponse {
    pub session_token: String,
}
