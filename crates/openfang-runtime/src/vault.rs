//! Encrypted file-based secret management.
//!
//! Provides a secure vault for long-lived secrets like API keys.
//! Uses AES-256-GCM for encryption and Argon2id for key derivation.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Default, Debug)]
struct VaultData {
    /// Salt used for key derivation (Base64).
    salt: String,
    /// Encrypted secrets mapping.
    /// Key -> (NonceHex, CiphertextHex)
    secrets: HashMap<String, (String, String)>,
}

#[derive(Clone)]
pub struct Vault {
    path: PathBuf,
}

impl Vault {
    /// Create a new vault instance using a master password or machine-specific seed.
    pub fn new(service_name: &str, home_dir: &Path) -> Self {
        let path = home_dir.join(format!("{}.vault.json", service_name));
        Self::open(path)
    }

    /// Open a vault at the specified path.
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
        }
    }

    fn load(&self) -> (VaultData, bool) {
        if !self.path.exists() {
            return (VaultData {
                salt: SaltString::generate(&mut rand::thread_rng()).to_string(),
                secrets: HashMap::new(),
            }, true);
        }
        let content = fs::read_to_string(&self.path).unwrap_or_default();
        let data: VaultData = serde_json::from_str(&content).unwrap_or_default();
        let is_empty = data.salt.is_empty();
        (data, is_empty)
    }

    fn save(&self, data: &VaultData) -> Result<(), String> {
        let content = serde_json::to_string(data).map_err(|e| e.to_string())?;
        
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        fs::write(&self.path, content).map_err(|e| e.to_string())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(&self.path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = fs::set_permissions(&self.path, perms);
            }
        }

        Ok(())
    }

    /// Store a secret in the encrypted vault.
    pub fn set_secret(&self, key: &str, mut secret: String) -> Result<(), String> {
        let (mut data, _is_new) = self.load();
        
        // Use the key derived based on data.salt
        let mut final_key = [0u8; 32];
        let mut master_pass = std::env::var("OPENFANG_VAULT_PASS").unwrap_or_else(|_| {
            dirs::home_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "default-fallback-pass".to_string())
        });
        
        if let Ok(salt) = SaltString::from_b64(&data.salt) {
             if let Ok(hash) = Argon2::default().hash_password(master_pass.as_bytes(), &salt) {
                 if let Some(output) = hash.hash {
                     let hb = output.as_ref();
                     final_key[..hb.len().min(32)].copy_from_slice(&hb[..hb.len().min(32)]);
                 }
             }
        }
        master_pass.zeroize();
        
        let cipher = Aes256Gcm::new_from_slice(&final_key).map_err(|_| "Key init failed")?;

        use rand::RngCore;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, secret.as_bytes())
            .map_err(|e| format!("Encryption failed: {e}"))?;
        
        secret.zeroize();

        data.secrets.insert(
            key.to_string(),
            (hex::encode(nonce_bytes), hex::encode(ciphertext)),
        );

        self.save(&data)
    }

    /// Retrieve a secret from the encrypted vault.
    pub fn get_secret(&self, key: &str) -> Option<String> {
        let (data, _) = self.load();
        let (nonce_hex, cipher_hex) = data.secrets.get(key)?;

        let nonce_bytes = hex::decode(nonce_hex).ok()?;
        let ciphertext = hex::decode(cipher_hex).ok()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Derive key based on loaded data.salt
        let mut final_key = [0u8; 32];
        let mut master_pass = std::env::var("OPENFANG_VAULT_PASS").unwrap_or_else(|_| {
            dirs::home_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "default-fallback-pass".to_string())
        });
        
        if let Ok(salt) = SaltString::from_b64(&data.salt) {
             if let Ok(hash) = Argon2::default().hash_password(master_pass.as_bytes(), &salt) {
                 if let Some(output) = hash.hash {
                     let hb = output.as_ref();
                     final_key[..hb.len().min(32)].copy_from_slice(&hb[..hb.len().min(32)]);
                 }
             }
        }
        master_pass.zeroize();

        let cipher = Aes256Gcm::new_from_slice(&final_key).ok()?;
        let plaintext_bytes = cipher.decrypt(nonce, ciphertext.as_slice()).ok()?;

        let mut plaintext = String::from_utf8(plaintext_bytes).ok()?;
        let result = Some(plaintext.clone());
        plaintext.zeroize();
        result
    }

    /// Delete a secret from the encrypted vault.
    pub fn delete_secret(&self, key: &str) -> Result<(), String> {
        let (mut data, _) = self.load();
        data.secrets.remove(key);
        self.save(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_vault_roundtrip() {
        std::env::set_var("OPENFANG_VAULT_PASS", "test-pass-123");

        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test_roundtrip.json");
        let vault = Vault::open(&vault_path);

        let key = "api-key";
        let secret = "sk-1234567890".to_string();

        vault.set_secret(key, secret.clone()).unwrap();

        let retrieved = vault.get_secret(key).expect("Secret should be found");
        assert_eq!(retrieved, secret);

        // Verify it persists with a new instance
        let vault2 = Vault::open(&vault_path);
        let retrieved2 = vault2.get_secret(key).expect("Secret should be found in new instance");
        assert_eq!(retrieved2, secret);

        vault.delete_secret(key).unwrap();
        assert!(vault.get_secret(key).is_none());

        std::env::remove_var("OPENFANG_VAULT_PASS");
    }
}
