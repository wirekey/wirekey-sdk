// #[async_trait::async_trait]
// pub trait SessionApi {
//     async fn get_sessions(&self) -> Result<Vec<SessionInfo>, ApiError>;
//     async fn get_session(&self, session_id: &str) -> Result<SessionInfo, ApiError>;
//     async fn get_session_clients(&self, session_id: &str) -> Result<Vec<ClientId>, ApiError>;
//     async fn add_client_to_session(&self, session_id: &str, client_id: &str) -> Result<(), ApiError>;
//     async fn remove_client_from_session(&self, session_id: &str, client_id: &str) -> Result<(), ApiError>;
//     async fn get_chain_keys(&self, session_id: &str) -> Result<ChainKeys, ApiError>;
//     async fn get_encryption_key(&self, session_id: &str) -> Result<EncryptionKey, ApiError>;
//     async fn rotate_encryption_key(&self, session_id: &str) -> Result<EncryptionKey, ApiError>;
// }