//! Core types for singleton management

use chia::protocol::{Bytes32, Coin};
use chia::puzzles::{EveProof, LineageProof, Proof};
use clvm_utils::TreeHash;

/// Lineage information for generating proofs
#[derive(Debug, Clone)]
pub enum SingletonLineage {
    /// First spend after launch (eve proof)
    Eve {
        /// The parent coin ID of the launcher (funding coin ID)
        launcher_parent_id: Bytes32,
        /// The singleton amount
        amount: u64,
    },
    /// Subsequent spends (lineage proof)
    Lineage {
        /// The parent singleton coin
        parent_coin: Coin,
        /// The parent's inner puzzle hash
        parent_inner_hash: TreeHash,
    },
}

impl SingletonLineage {
    /// Convert to a Proof for use in singleton solutions
    pub fn to_proof(&self) -> Proof {
        match self {
            SingletonLineage::Eve { launcher_parent_id, amount } => {
                Proof::Eve(EveProof {
                    parent_parent_coin_info: *launcher_parent_id,
                    parent_amount: *amount,
                })
            }
            SingletonLineage::Lineage { parent_coin, parent_inner_hash } => {
                Proof::Lineage(LineageProof {
                    parent_parent_coin_info: parent_coin.parent_coin_info,
                    parent_inner_puzzle_hash: (*parent_inner_hash).into(),
                    parent_amount: parent_coin.amount,
                })
            }
        }
    }

    /// Create eve lineage from funding coin info
    pub fn eve(funding_coin_id: Bytes32, singleton_amount: u64) -> Self {
        SingletonLineage::Eve {
            launcher_parent_id: funding_coin_id,
            amount: singleton_amount,
        }
    }

    /// Create lineage proof from parent coin and inner hash
    pub fn lineage(parent_coin: Coin, parent_inner_hash: TreeHash) -> Self {
        SingletonLineage::Lineage {
            parent_coin,
            parent_inner_hash,
        }
    }
}

/// Tracks an on-chain singleton's current state
#[derive(Debug, Clone)]
pub struct SingletonCoin {
    /// The launcher ID (singleton identity)
    pub launcher_id: Bytes32,
    /// The current unspent coin
    pub coin: Coin,
    /// Lineage for proof generation
    pub lineage: SingletonLineage,
}

impl SingletonCoin {
    /// Create a new SingletonCoin
    pub fn new(launcher_id: Bytes32, coin: Coin, lineage: SingletonLineage) -> Self {
        Self {
            launcher_id,
            coin,
            lineage,
        }
    }

    /// Get the proof for spending this singleton
    pub fn proof(&self) -> Proof {
        self.lineage.to_proof()
    }

    /// Get the coin ID
    pub fn coin_id(&self) -> Bytes32 {
        self.coin.coin_id()
    }
}

/// Result of launching a singleton
#[derive(Debug, Clone)]
pub struct LaunchResult {
    /// The launcher ID (singleton identity, same as network_id for network singletons)
    pub launcher_id: Bytes32,
    /// The newly created singleton coin
    pub coin: Coin,
    /// Conditions to include in the funding coin spend
    pub conditions: chia_wallet_sdk::types::Conditions,
}

/// Result of an action spend (generic over action-specific output)
#[derive(Debug, Clone)]
pub struct ActionSpendResult<T> {
    /// The recreated singleton coin (None if melted)
    pub new_coin: Option<Coin>,
    /// New lineage for next spend (None if melted)
    pub new_lineage: Option<SingletonLineage>,
    /// Action-specific output (child launcher IDs, etc.)
    pub output: T,
}

impl<T> ActionSpendResult<T> {
    /// Create result for a normal action (singleton recreated)
    pub fn normal(new_coin: Coin, new_lineage: SingletonLineage, output: T) -> Self {
        Self {
            new_coin: Some(new_coin),
            new_lineage: Some(new_lineage),
            output,
        }
    }

    /// Create result for a melt action (singleton destroyed)
    pub fn melted(output: T) -> Self {
        Self {
            new_coin: None,
            new_lineage: None,
            output,
        }
    }

    /// Check if the singleton was melted
    pub fn is_melted(&self) -> bool {
        self.new_coin.is_none()
    }
}

/// Marker type for actions that produce no specific output
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOutput;

/// Marker type for actions that melt (destroy) the singleton
#[derive(Debug, Clone, Copy)]
pub struct Melted;
