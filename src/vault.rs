use crate::crypto::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultStatus {
    Locked,
    Unlocked,
    Modified,
    Sealed,
}

impl Default for VaultStatus {
    fn default() -> Self {
        VaultStatus::Unlocked
    }
}

#[derive(Serialize, Deserialize)]
pub struct VaultRecord {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Vault {
    pub entries: HashMap<String, String>,
    #[serde(skip)]
    state: VaultStatus,
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.seal();
    }
}

impl Vault {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            state: VaultStatus::Unlocked,
        }
    }

    pub fn state(&self) -> VaultStatus {
        self.state
    }

    pub fn insert(&mut self, key: String, value: String) {
        if self.state == VaultStatus::Sealed {
            return;
        }
        self.entries.insert(key, value);
        self.state = VaultStatus::Modified;
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        if self.state == VaultStatus::Sealed || self.state == VaultStatus::Locked {
            return None;
        }
        self.entries.get(key)
    }

    /// Explicitly zeroizes all secret strings and transitions to Sealed state.
    pub fn seal(&mut self) {
        for (k, v) in self.entries.iter_mut() {
            k.zeroize();
            v.zeroize();
        }
        self.entries.clear();
        self.state = VaultStatus::Sealed;
    }

    pub fn read_salt_from_file<P: AsRef<Path>>(path: P) -> Result<[u8; SALT_LEN], Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let record: VaultRecord = serde_json::from_str(&content)?;
        let salt_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &record.salt)?;
        if salt_bytes.len() != SALT_LEN {
            return Err("Invalid salt length in vault record".into());
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_bytes);
        Ok(salt)
    }

    pub fn save_to_file<P: AsRef<Path>>(&mut self, path: P, master_key: &SensitiveKey) -> Result<(), Box<dyn std::error::Error>> {
        self.save_with_salt(path, master_key, &generate_salt())
    }

    pub fn save_with_salt<P: AsRef<Path>>(&mut self, path: P, master_key: &SensitiveKey, salt: &[u8; SALT_LEN]) -> Result<(), Box<dyn std::error::Error>> {
        let mut serialized = serde_json::to_vec(&self)?;
        let nonce = generate_nonce();
        let encrypted = encrypt_payload(master_key, &nonce, &serialized)?;
        serialized.zeroize();

        let record = VaultRecord {
            salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, salt),
            nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce),
            ciphertext: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, encrypted),
        };

        let file_data = serde_json::to_string_pretty(&record)?;
        fs::write(path, file_data)?;
        self.state = VaultStatus::Unlocked;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P, master_key: &SensitiveKey) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let record: VaultRecord = serde_json::from_str(&content)?;

        let nonce_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &record.nonce)?;
        let cipher_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &record.ciphertext)?;

        if nonce_bytes.len() != 12 {
            return Err("Invalid nonce length in vault record".into());
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);

        let decrypted = decrypt_payload(master_key, &nonce, &cipher_bytes)?;
        let mut vault: Vault = serde_json::from_slice(&decrypted)?;
        vault.state = VaultStatus::Unlocked;
        Ok(vault)
    }
}
