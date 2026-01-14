//! Key derivation and synthetic key computation.

use chia::bls::{PublicKey, SecretKey, DerivableKey};
use chia::puzzles::DeriveSynthetic;
use crate::error::{WalletError, WalletResult};
use chia_puzzle_types::standard::DEFAULT_HIDDEN_PUZZLE_HASH;

/// Key derivation utilities following Chia HD path standards.
pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive a key using Chia standard HD path: m/12381/8444/2/{index}
    ///
    /// This is the standard derivation path for Chia wallets.
    pub fn derive_wallet_key(master_sk: &SecretKey, index: u32) -> SecretKey {
        master_sk
            .derive_hardened(12381)
            .derive_hardened(8444)
            .derive_hardened(2)
            .derive_unhardened(index)
    }

    /// Generate a BIP39 mnemonic from random entropy.
    pub fn generate_mnemonic() -> WalletResult<String> {
        use bip39::{Language, Mnemonic};
        use rand::RngCore;

        // Generate 32 bytes of entropy for 24-word mnemonic (256 bits)
        let mut entropy = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);

        // Create BIP39 mnemonic from entropy
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| WalletError::Bip39(format!("Failed to generate mnemonic: {}", e)))?;

        Ok(mnemonic.to_string())
    }

    /// Derive a secret key from a BIP39 mnemonic.
    pub fn derive_key_from_mnemonic(mnemonic: &str) -> WalletResult<SecretKey> {
        use bip39::{Language, Mnemonic};

        // Parse and validate the BIP39 mnemonic
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)
            .map_err(|e| WalletError::InvalidMnemonic(format!("Invalid mnemonic: {}", e)))?;

        // Generate seed from mnemonic with empty passphrase (Chia standard)
        let seed = mnemonic.to_seed("");

        // Derive master key from seed (use first 32 bytes as seed for Chia BLS key)
        // Chia uses a specific derivation scheme - use first 32 bytes of BIP39 seed
        let seed_bytes: [u8; 32] = seed[..32]
            .try_into()
            .map_err(|_| WalletError::KeyDerivation("Failed to derive seed bytes".into()))?;

        Ok(SecretKey::from_seed(&seed_bytes))
    }

    /// Generate a random secret key from random seed.
    pub fn generate_random_key() -> SecretKey {
        use rand::RngCore;

        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        SecretKey::from_seed(&seed)
    }
}

/// Synthetic key computation for standard Chia puzzles.
pub struct SyntheticKey;

impl SyntheticKey {
    /// Compute synthetic public key from original key and default hidden puzzle hash.
    ///
    /// The synthetic key is derived using the standard Chia derivation path
    /// for the default hidden puzzle. This is used for standard transaction puzzles.
    pub fn compute_synthetic_public_key(public_key: &PublicKey) -> PublicKey {
        // DEFAULT_HIDDEN_PUZZLE_HASH is already [u8; 32] from chia-puzzle-types
        public_key.derive_synthetic_hidden(&DEFAULT_HIDDEN_PUZZLE_HASH)
    }

    /// Compute synthetic public key bytes from raw public key bytes.
    ///
    /// This is a version-agnostic variant that works with raw bytes instead
    /// of a specific PublicKey type, useful for cross-crate compatibility.
    pub fn compute_synthetic_public_key_bytes(pk_bytes: &[u8; 48]) -> [u8; 48] {
        let pk = PublicKey::from_bytes(pk_bytes).expect("valid public key");
        Self::compute_synthetic_public_key(&pk).to_bytes()
    }

    /// Compute synthetic secret key from original secret key.
    ///
    /// The synthetic secret key is: sk + scalar_from_hash(pk || default_hidden_puzzle_hash)
    /// This is used for signing standard transaction spends in Chia.
    pub fn compute_synthetic_secret_key(secret_key: &SecretKey) -> SecretKey {
        // DEFAULT_HIDDEN_PUZZLE_HASH is already [u8; 32] from chia-puzzle-types
        secret_key.derive_synthetic_hidden(&DEFAULT_HIDDEN_PUZZLE_HASH)
    }

    /// Compute synthetic secret key bytes from raw secret key bytes.
    ///
    /// This is a version-agnostic variant that works with raw bytes instead
    /// of a specific SecretKey type, useful for cross-crate compatibility.
    pub fn compute_synthetic_secret_key_bytes(sk_bytes: &[u8; 32]) -> [u8; 32] {
        let sk = SecretKey::from_bytes(sk_bytes).expect("valid secret key");
        Self::compute_synthetic_secret_key(&sk).to_bytes()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthetic_key_derivation() {
        let sk_bytes = [1u8; 32];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = sk.public_key();

        let synthetic = SyntheticKey::compute_synthetic_public_key(&pk);

        // Synthetic key should be different from original
        assert_ne!(synthetic.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn test_synthetic_secret_key_matches_public_key() {
        // Test that synthetic_sk.public_key() == synthetic_pk
        let sk_bytes = [42u8; 32];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = sk.public_key();

        // Compute synthetic keys
        let synthetic_pk = SyntheticKey::compute_synthetic_public_key(&pk);
        let synthetic_sk = SyntheticKey::compute_synthetic_secret_key(&sk);

        // The synthetic secret key's public key should match the synthetic public key
        assert_eq!(
            synthetic_sk.public_key().to_bytes(),
            synthetic_pk.to_bytes(),
            "Synthetic secret key's public key should match synthetic public key"
        );
    }

    #[test]
    fn test_bytes_variant_matches_typed() {
        let sk_bytes = [42u8; 32];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();

        // Bytes variant should produce same result as typed variant
        let synthetic_pk = SyntheticKey::compute_synthetic_public_key(&pk);
        let synthetic_pk_from_bytes = SyntheticKey::compute_synthetic_public_key_bytes(&pk_bytes);

        assert_eq!(synthetic_pk.to_bytes(), synthetic_pk_from_bytes);

        let synthetic_sk = SyntheticKey::compute_synthetic_secret_key(&sk);
        let synthetic_sk_from_bytes = SyntheticKey::compute_synthetic_secret_key_bytes(&sk_bytes);

        assert_eq!(synthetic_sk.to_bytes(), synthetic_sk_from_bytes);
    }

    #[test]
    fn test_mnemonic_generation() {
        let mnemonic = KeyDerivation::generate_mnemonic().unwrap();
        assert!(!mnemonic.is_empty());

        // Should be able to derive key from it
        let sk = KeyDerivation::derive_key_from_mnemonic(&mnemonic).unwrap();
        assert_eq!(sk.to_bytes().len(), 32);
    }

    #[test]
    fn test_wallet_key_derivation() {
        let master_sk = KeyDerivation::generate_random_key();

        // Derive multiple keys
        let sk0 = KeyDerivation::derive_wallet_key(&master_sk, 0);
        let sk1 = KeyDerivation::derive_wallet_key(&master_sk, 1);

        // Should be different
        assert_ne!(sk0.to_bytes(), sk1.to_bytes());
    }
}
