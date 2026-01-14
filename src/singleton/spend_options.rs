//! Spend bundle options and broadcast configuration

use std::time::Duration;

use chia::protocol::{Bytes32, Coin};

/// Options for spend bundle handling
///
/// Allows configuring whether to broadcast immediately, add fees,
/// and wait for confirmation.
#[derive(Clone)]
pub struct SpendOptions {
    /// Fee amount to include (0 = no fee)
    pub fee: u64,

    /// Fee coin to spend (required if fee > 0)
    pub fee_coin: Option<Coin>,

    /// Puzzle hash to send change to (required if fee_coin provided)
    pub change_puzzle_hash: Option<Bytes32>,

    /// Whether to wait for confirmation after broadcast
    pub wait_for_confirmation: bool,

    /// Timeout for confirmation (default 5 minutes)
    pub confirmation_timeout: Duration,
}

impl Default for SpendOptions {
    fn default() -> Self {
        Self {
            fee: 0,
            fee_coin: None,
            change_puzzle_hash: None,
            wait_for_confirmation: false,
            confirmation_timeout: Duration::from_secs(300),
        }
    }
}

impl SpendOptions {
    /// Create options with no fee
    pub fn no_fee() -> Self {
        Self::default()
    }

    /// Create options with a fee
    pub fn with_fee(fee: u64, fee_coin: Coin, change_puzzle_hash: Bytes32) -> Self {
        Self {
            fee,
            fee_coin: Some(fee_coin),
            change_puzzle_hash: Some(change_puzzle_hash),
            ..Default::default()
        }
    }

    /// Set whether to wait for confirmation
    pub fn wait(mut self, wait: bool) -> Self {
        self.wait_for_confirmation = wait;
        self
    }

    /// Set confirmation timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.confirmation_timeout = timeout;
        self
    }

    /// Check if fee is configured
    pub fn has_fee(&self) -> bool {
        self.fee > 0 && self.fee_coin.is_some()
    }
}

/// Fee configuration for spend bundles
#[derive(Debug, Clone)]
pub struct FeeOptions {
    /// The coin to use for fees
    pub fee_coin: Coin,

    /// Fee amount in mojos
    pub fee_amount: u64,

    /// Puzzle hash for change output
    pub change_puzzle_hash: Bytes32,
}

impl FeeOptions {
    /// Create new fee options
    pub fn new(fee_coin: Coin, fee_amount: u64, change_puzzle_hash: Bytes32) -> Self {
        Self {
            fee_coin,
            fee_amount,
            change_puzzle_hash,
        }
    }

    /// Calculate change amount
    pub fn change_amount(&self) -> u64 {
        self.fee_coin.amount.saturating_sub(self.fee_amount)
    }
}
