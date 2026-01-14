//! Generic driver for Action Layer (CHIP-0050) spend construction
//!
//! This crate provides utilities for building spends that use the Action Layer pattern:
//! - `PuzzleModule` - Load and curry puzzles with typed arguments
//! - `ActionLayerConfig` - Configure and build action layer spends
//! - Singleton helpers for building singleton spends with action layer inner puzzles
//!
//! # Design Philosophy
//!
//! This crate is designed to work with caller-provided curry args types. The key pattern is:
//!
//! ```rust,ignore
//! // Caller defines their own curry args struct with #[clvm(curry)]
//! #[derive(Debug, Clone, ToClvm, FromClvm)]
//! #[clvm(curry)]
//! pub struct MyCurryArgs {
//!     pub some_hash: Bytes32,
//! }
//!
//! // Use PuzzleModule to curry and hash
//! let puzzle = PuzzleModule::from_hex(MY_PUZZLE_HEX);
//! let curried_hash = puzzle.curry_tree_hash(MyCurryArgs { some_hash });
//! let curried_ptr = puzzle.curry_puzzle(ctx, MyCurryArgs { some_hash })?;
//! ```

mod puzzle;
mod action_layer;
mod singleton;
mod error;

pub use puzzle::PuzzleModule;
pub use action_layer::ActionLayerConfig;
pub use singleton::*;
pub use error::DriverError;

// Re-export commonly used types from dependencies
pub use chia::protocol::{Bytes32, Coin, CoinSpend};
pub use chia::puzzles::{Proof, EveProof, LineageProof};
pub use chia_wallet_sdk::driver::SpendContext;
pub use clvm_utils::TreeHash;
pub use clvmr::NodePtr;
