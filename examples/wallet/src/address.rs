//! Address and puzzle hash utilities.

use chia::bls::PublicKey;
use chia::puzzles::standard::StandardArgs;
use crate::error::{WalletError, WalletResult};

/// Address utilities for Chia addresses.
pub struct AddressUtils;

impl AddressUtils {
    /// Compute puzzle hash from public key.
    ///
    /// This computes the tree hash of p2_delegated_puzzle_or_hidden_puzzle
    /// curried with the synthetic public key.
    pub fn compute_puzzle_hash(public_key: &PublicKey) -> [u8; 32] {
        // Use the correct Chia standard puzzle hash computation
        let tree_hash = StandardArgs::curry_tree_hash(public_key.clone());
        tree_hash.to_bytes()
    }

    /// Compute address from public key (mainnet).
    pub fn compute_address(public_key: &PublicKey) -> String {
        let puzzle_hash = Self::compute_puzzle_hash(public_key);
        Self::puzzle_hash_to_address(&puzzle_hash, "xch")
    }

    /// Compute testnet address from public key.
    pub fn compute_testnet_address(public_key: &PublicKey) -> String {
        let puzzle_hash = Self::compute_puzzle_hash(public_key);
        Self::puzzle_hash_to_address(&puzzle_hash, "txch")
    }

    /// Convert puzzle hash to bech32m address.
    pub fn puzzle_hash_to_address(puzzle_hash: &[u8; 32], prefix: &str) -> String {
        use bech32::{Bech32m, Hrp};

        let hrp = Hrp::parse(prefix).expect("valid hrp");
        bech32::encode::<Bech32m>(hrp, puzzle_hash.as_slice()).expect("valid bech32m encoding")
    }

    /// Parse destination (address or puzzle hash) to puzzle hash bytes.
    pub fn parse_destination(dest: &str) -> WalletResult<[u8; 32]> {
        if dest.starts_with("xch1") || dest.starts_with("txch1") {
            // Bech32m address
            let (_, data) = bech32::decode(dest)
                .map_err(|e| WalletError::InvalidAddress(format!("Invalid address: {:?}", e)))?;

            if data.len() != 32 {
                return Err(WalletError::InvalidAddress(format!(
                    "Invalid address length: expected 32 bytes, got {}",
                    data.len()
                )));
            }

            let mut puzzle_hash = [0u8; 32];
            puzzle_hash.copy_from_slice(&data);
            Ok(puzzle_hash)
        } else {
            // Hex puzzle hash
            let hex_str = dest.strip_prefix("0x").unwrap_or(dest);
            let bytes = hex::decode(hex_str)
                .map_err(|e| WalletError::InvalidAddress(format!("Invalid puzzle hash hex: {}", e)))?;

            if bytes.len() != 32 {
                return Err(WalletError::InvalidAddress(format!(
                    "Puzzle hash must be 32 bytes, got {}",
                    bytes.len()
                )));
            }

            let mut puzzle_hash = [0u8; 32];
            puzzle_hash.copy_from_slice(&bytes);
            Ok(puzzle_hash)
        }
    }
}

/// Address type wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// The puzzle hash
    pub puzzle_hash: [u8; 32],
    /// The bech32m encoded address
    pub bech32: String,
}

impl Address {
    /// Create an address from a puzzle hash (mainnet).
    pub fn from_puzzle_hash(puzzle_hash: [u8; 32]) -> Self {
        let bech32 = AddressUtils::puzzle_hash_to_address(&puzzle_hash, "xch");
        Self { puzzle_hash, bech32 }
    }

    /// Create a testnet address from a puzzle hash.
    pub fn from_puzzle_hash_testnet(puzzle_hash: [u8; 32]) -> Self {
        let bech32 = AddressUtils::puzzle_hash_to_address(&puzzle_hash, "txch");
        Self { puzzle_hash, bech32 }
    }

    /// Create an address from a public key (mainnet).
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let puzzle_hash = AddressUtils::compute_puzzle_hash(public_key);
        Self::from_puzzle_hash(puzzle_hash)
    }

    /// Create a testnet address from a public key.
    pub fn from_public_key_testnet(public_key: &PublicKey) -> Self {
        let puzzle_hash = AddressUtils::compute_puzzle_hash(public_key);
        Self::from_puzzle_hash_testnet(puzzle_hash)
    }

    /// Parse an address from a string.
    pub fn from_string(s: &str) -> WalletResult<Self> {
        let puzzle_hash = AddressUtils::parse_destination(s)?;
        Ok(Self {
            puzzle_hash,
            bech32: s.to_string(),
        })
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.bech32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia::bls::SecretKey;

    #[test]
    fn test_address_computation() {
        let sk = SecretKey::from_bytes(&[1u8; 32]).unwrap();
        let pk = sk.public_key();

        let address = Address::from_public_key(&pk);
        assert!(address.bech32.starts_with("xch1"));
        assert_eq!(address.puzzle_hash.len(), 32);
    }

    #[test]
    fn test_address_parsing() {
        let sk = SecretKey::from_bytes(&[1u8; 32]).unwrap();
        let pk = sk.public_key();
        let address = Address::from_public_key(&pk);

        // Parse back
        let parsed = Address::from_string(&address.bech32).unwrap();
        assert_eq!(parsed.puzzle_hash, address.puzzle_hash);
    }
}
