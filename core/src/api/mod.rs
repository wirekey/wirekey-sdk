//! Remote server API abstractions for the WireKey SDK

mod key_management;
mod error;
mod prekey_bundle;
mod private_keys;
mod api_client;
mod auth;
mod responses;
mod http_sender;
mod rng_provider;

#[cfg(test)]
mod mock_sender;
#[cfg(test)]
mod mock_rng_provider;
#[cfg(test)]
mod key_management_tests;
#[cfg(test)]
mod api_client_tests;
#[cfg(test)]
mod auth_tests;
#[cfg(test)]
mod mock_opaque_sender;
#[cfg(test)]
mod test_utils;

pub use key_management::KeyManagementApi;
pub use api_client::ApiClient;
pub use error::Error;
pub use prekey_bundle::{PreKeyBundle, PublicSignedPreKey, PublicOneTimePreKey};
pub use private_keys::{PrivateKeys, PrivateSignedPreKey, PrivateOneTimePreKey};
pub use auth::AuthApi;
  