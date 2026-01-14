//! Wallet storage and file management.

use crate::error::{WalletError, WalletResult};
use chia::bls::SecretKey;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Information about a stored wallet.
#[derive(Debug, Clone)]
pub struct WalletInfo {
    /// Wallet name
    pub name: String,
    /// Path to wallet file
    pub path: PathBuf,
}

/// Wallet storage operations.
pub struct WalletStorage;

impl WalletStorage {
    /// Get the default wallet directory.
    pub fn wallet_dir() -> WalletResult<PathBuf> {
        let dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("puzzle_tests")
            .join("wallets");
        Ok(dir)
    }

    /// Get the path to a wallet file.
    pub fn wallet_path(name: &str) -> WalletResult<PathBuf> {
        let wallet_dir = Self::wallet_dir()?;
        Ok(wallet_dir.join(format!("{}.wallet", name)))
    }

    /// List all available wallets.
    pub fn list_wallets() -> WalletResult<Vec<WalletInfo>> {
        let wallet_dir = Self::wallet_dir()?;

        if !wallet_dir.exists() {
            return Ok(Vec::new());
        }

        let entries: Vec<_> = std::fs::read_dir(&wallet_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "wallet")
                    .unwrap_or(false)
            })
            .map(|e| WalletInfo {
                name: e
                    .path()
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default(),
                path: e.path(),
            })
            .collect();

        Ok(entries)
    }

    /// Check if a wallet exists.
    pub fn wallet_exists(name: &str) -> WalletResult<bool> {
        let wallet_path = Self::wallet_path(name)?;
        Ok(wallet_path.exists())
    }

    /// Save an encrypted wallet to disk.
    pub fn save_encrypted_wallet(
        path: &Path,
        secret_key: &SecretKey,
        passphrase: &str,
    ) -> WalletResult<()> {
        // Simple XOR encryption with hashed passphrase (not production-grade)
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        let key: [u8; 32] = hasher.finalize().into();

        let sk_bytes = secret_key.to_bytes();
        let encrypted: Vec<u8> = sk_bytes
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 32])
            .collect();

        // Create directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, encrypted)?;
        Ok(())
    }

    /// Load an encrypted wallet from disk.
    pub fn load_encrypted_wallet(path: &Path, passphrase: &str) -> WalletResult<SecretKey> {
        let encrypted = std::fs::read(path)?;

        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        let key: [u8; 32] = hasher.finalize().into();

        let decrypted: Vec<u8> = encrypted
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 32])
            .collect();

        let sk_bytes: [u8; 32] = decrypted
            .try_into()
            .map_err(|_| WalletError::InvalidPassphrase)?;

        SecretKey::from_bytes(&sk_bytes).map_err(|_| WalletError::InvalidPassphrase)
    }
}
