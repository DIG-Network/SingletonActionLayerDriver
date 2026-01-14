//! Error types for wallet operations.

use thiserror::Error;

/// Result type for wallet operations.
pub type WalletResult<T> = std::result::Result<T, WalletError>;

/// Errors that can occur during wallet operations.
#[derive(Error, Debug)]
pub enum WalletError {
    /// Wallet not found
    #[error("Wallet not found: {0}")]
    WalletNotFound(String),

    /// Invalid passphrase
    #[error("Invalid passphrase")]
    InvalidPassphrase,

    /// Wallet already exists
    #[error("Wallet already exists: {0}")]
    WalletExists(String),

    /// Invalid mnemonic
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Invalid secret key
    #[error("Invalid secret key")]
    InvalidSecretKey,

    /// Invalid address
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid amount
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    /// Transaction error
    #[error("Transaction error: {0}")]
    Transaction(String),

    /// Key derivation error
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Hex decode error
    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// Bech32 decode error
    #[error("Bech32 decode error: {0}")]
    Bech32Decode(String),

    /// BIP39 error
    #[error("BIP39 error: {0}")]
    Bip39(String),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Other error
    #[error("Other error: {0}")]
    Other(String),
}
