pub mod crypto;
pub mod vault;

pub use crypto::{derive_key, encrypt_payload, decrypt_payload, CryptoError};
pub use vault::{Vault, VaultRecord};
