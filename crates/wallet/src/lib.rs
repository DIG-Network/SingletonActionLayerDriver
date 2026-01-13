//! L2 Wallet Library
//!
//! This crate provides wallet management and transaction utilities for Chia L2 consensus.
//! It encapsulates all wallet functionality including key management, address derivation,
//! transaction signing, and synthetic key computation.
//!
//! # Features
//!
//! - **Wallet Management**: Create, import, load, and save encrypted wallets
//! - **Key Derivation**: HD key derivation following Chia standards (m/12381/8444/2/0)
//! - **Address Utilities**: Compute addresses and puzzle hashes from public keys
//! - **Transaction Signing**: Sign coin spends for standard transactions
//! - **Synthetic Keys**: Compute synthetic public/secret keys for standard puzzles
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use l2_wallet::{WalletManager, DerivationPath};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a new wallet
//! let manager = WalletManager::new();
//! let wallet = manager.create_wallet("my_wallet", "passphrase", true)?;
//!
//! // Load an existing wallet
//! let loaded = manager.load_wallet("my_wallet", "passphrase")?;
//!
//! // Derive address
//! let address = loaded.derive_address(0)?;
//! println!("Address: {}", address);
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

mod error;
mod manager;
mod keys;
mod address;
mod transaction;
mod storage;

pub use error::{WalletError, WalletResult};
pub use manager::{WalletManager, Wallet, DerivationPath};
pub use keys::{SyntheticKey, KeyDerivation};
pub use address::{Address, AddressUtils};
pub use transaction::{TransactionSigner, SigningContext};
pub use storage::{WalletStorage, WalletInfo};

/// Re-export commonly used types
pub use chia::bls::{PublicKey, SecretKey};
pub use chia::protocol::{Coin, CoinSpend};

// Type aliases for BLS types (using chia 0.32 SDK types)
/// Secret key type alias for Chia BLS operations
pub type ChiaBlsSecretKey = chia::bls::SecretKey;
/// Public key type alias for Chia BLS operations
pub type ChiaBlsPublicKey = chia::bls::PublicKey;
