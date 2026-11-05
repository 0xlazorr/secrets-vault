use crate::crypto::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct VaultRecord {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Vault {
    pub entries: HashMap<String, String>,
}

impl Vault {
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    pub fn insert(&mut self, key: String, value: String) {
        self.entries.insert(key, value);
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.entries.get(key)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P, master_key: &SensitiveKey) -> Result<(), Box<dyn std::error::Error>> {
        let serialized = serde_json::to_vec(&self)?;
        let salt = generate_salt();
        let nonce = generate_nonce();
        let encrypted = encrypt_payload(master_key, &nonce, &serialized)?;

        let record = VaultRecord {
            salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, salt),
            nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce),
            ciphertext: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, encrypted),
        };

        let file_data = serde_json::to_string_pretty(&record)?;
        fs::write(path, file_data)?;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P, master_key: &SensitiveKey) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let record: VaultRecord = serde_json::from_str(&content)?;

        let nonce_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &record.nonce)?;
        let cipher_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &record.ciphertext)?;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);

        let decrypted = decrypt_payload(master_key, &nonce, &cipher_bytes)?;
        let vault: Vault = serde_json::from_slice(&decrypted)?;
        Ok(vault)
    }
}
