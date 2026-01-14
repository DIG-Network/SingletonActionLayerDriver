//! Wallet manager for creating, loading, and managing wallets.

use crate::address::{Address, AddressUtils};
use crate::error::{WalletError, WalletResult};
use crate::keys::{KeyDerivation, SyntheticKey};
use crate::storage::WalletStorage;
use chia::bls::{PublicKey, SecretKey};

/// Derivation path for wallet keys.
#[derive(Debug, Clone, Copy)]
pub struct DerivationPath {
    /// The index in the derivation path (m/12381/8444/2/{index})
    pub index: u32,
}

impl DerivationPath {
    /// Create a new derivation path with the given index.
    pub fn new(index: u32) -> Self {
        Self { index }
    }

    /// Default derivation path (index 0).
    pub fn default_path() -> Self {
        Self { index: 0 }
    }
}

impl Default for DerivationPath {
    fn default() -> Self {
        Self::default_path()
    }
}

/// A loaded wallet instance.
#[derive(Debug, Clone)]
pub struct Wallet {
    /// Master secret key
    master_sk: SecretKey,
    /// Wallet name
    name: String,
}

impl Wallet {
    /// Get the master public key.
    pub fn master_public_key(&self) -> PublicKey {
        self.master_sk.public_key()
    }

    /// Get the wallet name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Derive a wallet key at the given index.
    pub fn derive_key(&self, path: DerivationPath) -> SecretKey {
        KeyDerivation::derive_wallet_key(&self.master_sk, path.index)
    }

    /// Derive an address at the given index (mainnet).
    pub fn derive_address(&self, index: u32) -> WalletResult<Address> {
        let derived_sk = self.derive_key(DerivationPath::new(index));
        let derived_pk = derived_sk.public_key();
        Ok(Address::from_public_key(&derived_pk))
    }

    /// Derive a testnet address at the given index.
    pub fn derive_testnet_address(&self, index: u32) -> WalletResult<Address> {
        let derived_sk = self.derive_key(DerivationPath::new(index));
        let derived_pk = derived_sk.public_key();
        Ok(Address::from_public_key_testnet(&derived_pk))
    }

    /// Get the puzzle hash for the address at the given index.
    pub fn puzzle_hash(&self, index: u32) -> WalletResult<[u8; 32]> {
        let derived_sk = self.derive_key(DerivationPath::new(index));
        let derived_pk = derived_sk.public_key();
        Ok(AddressUtils::compute_puzzle_hash(&derived_pk))
    }

    /// Get the synthetic public key for the address at the given index.
    pub fn synthetic_public_key(&self, index: u32) -> PublicKey {
        let derived_sk = self.derive_key(DerivationPath::new(index));
        let derived_pk = derived_sk.public_key();
        SyntheticKey::compute_synthetic_public_key(&derived_pk)
    }

    /// Get the synthetic secret key for the address at the given index.
    pub fn synthetic_secret_key(&self, index: u32) -> SecretKey {
        let derived_sk = self.derive_key(DerivationPath::new(index));
        SyntheticKey::compute_synthetic_secret_key(&derived_sk)
    }

    /// Get the master secret key (use with caution).
    pub fn master_secret_key(&self) -> &SecretKey {
        &self.master_sk
    }
}

/// Wallet manager for creating and loading wallets.
pub struct WalletManager;

impl WalletManager {
    /// Create a new wallet manager.
    pub fn new() -> Self {
        Self
    }

    /// Create a new wallet with a random key.
    pub fn create_wallet(
        &self,
        name: &str,
        passphrase: &str,
        overwrite: bool,
    ) -> WalletResult<Wallet> {
        let wallet_path = WalletStorage::wallet_path(name)?;

        if wallet_path.exists() && !overwrite {
            return Err(WalletError::WalletExists(name.to_string()));
        }

        // Generate random secret key
        let secret_key = KeyDerivation::generate_random_key();

        // Save encrypted wallet
        WalletStorage::save_encrypted_wallet(wallet_path.as_path(), &secret_key, passphrase)?;

        Ok(Wallet {
            master_sk: secret_key,
            name: name.to_string(),
        })
    }

    /// Create a wallet from a mnemonic.
    pub fn create_wallet_from_mnemonic(
        &self,
        name: &str,
        mnemonic: &str,
        passphrase: &str,
        overwrite: bool,
    ) -> WalletResult<Wallet> {
        let wallet_path = WalletStorage::wallet_path(name)?;

        if wallet_path.exists() && !overwrite {
            return Err(WalletError::WalletExists(name.to_string()));
        }

        // Derive key from mnemonic
        let secret_key = KeyDerivation::derive_key_from_mnemonic(mnemonic)?;

        // Save encrypted wallet
        WalletStorage::save_encrypted_wallet(wallet_path.as_path(), &secret_key, passphrase)?;

        Ok(Wallet {
            master_sk: secret_key,
            name: name.to_string(),
        })
    }

    /// Create a wallet from a secret key (hex format).
    #[allow(unused_variables)]
    pub fn create_wallet_from_secret_key(
        &self,
        name: &str,
        secret_key_hex: &str,
        passphrase: &str,
        overwrite: bool,
    ) -> WalletResult<Wallet> {
        let wallet_path = WalletStorage::wallet_path(name)?;

        if wallet_path.exists() && !overwrite {
            return Err(WalletError::WalletExists(name.to_string()));
        }

        // Parse secret key
        let sk_hex = secret_key_hex.strip_prefix("0x").unwrap_or(secret_key_hex);
        let sk_bytes = hex::decode(sk_hex).map_err(|_| WalletError::InvalidSecretKey)?;
        let sk_array: [u8; 32] = sk_bytes
            .try_into()
            .map_err(|_| WalletError::InvalidSecretKey)?;
        let secret_key =
            SecretKey::from_bytes(&sk_array).map_err(|_| WalletError::InvalidSecretKey)?;

        // Save encrypted wallet
        WalletStorage::save_encrypted_wallet(wallet_path.as_path(), &secret_key, passphrase)?;

        Ok(Wallet {
            master_sk: secret_key,
            name: name.to_string(),
        })
    }

    /// Load an existing wallet.
    pub fn load_wallet(&self, name: &str, passphrase: &str) -> WalletResult<Wallet> {
        let wallet_path = WalletStorage::wallet_path(name)?;

        if !wallet_path.exists() {
            return Err(WalletError::WalletNotFound(name.to_string()));
        }

        let secret_key = WalletStorage::load_encrypted_wallet(&wallet_path, passphrase)?;

        Ok(Wallet {
            master_sk: secret_key,
            name: name.to_string(),
        })
    }

    /// List all available wallets.
    pub fn list_wallets(&self) -> WalletResult<Vec<crate::storage::WalletInfo>> {
        WalletStorage::list_wallets()
    }

    /// Check if a wallet exists.
    pub fn wallet_exists(&self, name: &str) -> WalletResult<bool> {
        WalletStorage::wallet_exists(name)
    }

    /// Generate a mnemonic for backup.
    pub fn generate_mnemonic(&self) -> WalletResult<String> {
        KeyDerivation::generate_mnemonic()
    }
}

impl Default for WalletManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_load_wallet() {
        let manager = WalletManager::new();

        // In a real test, we'd use a test-specific directory
        let wallet = manager
            .create_wallet("test_wallet", "test_pass", true)
            .unwrap();

        // Load it back
        let loaded = manager.load_wallet("test_wallet", "test_pass").unwrap();

        assert_eq!(
            wallet.master_public_key().to_bytes(),
            loaded.master_public_key().to_bytes()
        );
    }

    #[test]
    fn test_wallet_address_derivation() {
        let manager = WalletManager::new();
        let wallet = manager.create_wallet("test_addr", "pass", true).unwrap();

        let addr0 = wallet.derive_address(0).unwrap();
        let addr1 = wallet.derive_address(1).unwrap();

        // Different indices should produce different addresses
        assert_ne!(addr0.puzzle_hash, addr1.puzzle_hash);
    }
}
