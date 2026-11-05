use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Argon2 key derivation failure: {0}")]
    KdfError(String),
    #[error("Aead encryption error")]
    EncryptionError,
    #[error("Aead decryption error: authentication tag mismatch or corrupted data")]
    DecryptionError,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SensitiveKey(pub [u8; 32]);

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<SensitiveKey, CryptoError> {
    let mut key_bytes = [0u8; 32];
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(passphrase, salt, &mut key_bytes)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    Ok(SensitiveKey(key_bytes))
}

pub fn encrypt_payload(key: &SensitiveKey, nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher_key = Key::from_slice(&key.0);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let cipher_nonce = Nonce::from_slice(nonce);

    cipher.encrypt(cipher_nonce, plaintext).map_err(|_| CryptoError::EncryptionError)
}

pub fn decrypt_payload(key: &SensitiveKey, nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher_key = Key::from_slice(&key.0);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let cipher_nonce = Nonce::from_slice(nonce);

    cipher.decrypt(cipher_nonce, ciphertext).map_err(|_| CryptoError::DecryptionError)
}
