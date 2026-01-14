//! Puzzle loading and currying utilities
//!
//! The key insight is that callers should define their own curry args types with `#[clvm(curry)]`.
//! This module provides utilities to work with those types via `CurriedProgram`.

use chia_wallet_sdk::driver::SpendContext;
use clvm_traits::ToClvm;
use clvm_utils::{CurriedProgram, TreeHash};
use clvmr::serde::node_from_bytes;
use clvmr::{Allocator, NodePtr};

use crate::DriverError;

/// A compiled puzzle module that can be curried with typed arguments.
///
/// # Example
///
/// ```rust,ignore
/// // Define curry args with #[clvm(curry)]
/// #[derive(Debug, Clone, ToClvm, FromClvm)]
/// #[clvm(curry)]
/// pub struct MyCurryArgs {
///     pub inner_puzzle_hash: Bytes32,
/// }
///
/// // Load puzzle
/// let puzzle = PuzzleModule::from_hex(MY_PUZZLE_HEX)?;
///
/// // Compute curried hash using CurriedProgram directly
/// let args = MyCurryArgs { inner_puzzle_hash: some_hash };
/// let curried_hash = CurriedProgram {
///     program: puzzle.mod_hash(),
///     args: args.clone(),
/// }.tree_hash();
///
/// // Build curried puzzle for spending
/// let curried_ptr = puzzle.curry_puzzle(ctx, args)?;
/// ```
#[derive(Clone)]
pub struct PuzzleModule {
    mod_hash: TreeHash,
    mod_bytes: Vec<u8>,
}

impl PuzzleModule {
    /// Create a PuzzleModule from raw puzzle bytes
    pub fn new(bytes: Vec<u8>) -> Result<Self, DriverError> {
        let mut alloc = Allocator::new();
        let ptr = node_from_bytes(&mut alloc, &bytes)
            .map_err(|e| DriverError::PuzzleParse(format!("{:?}", e)))?;
        let mod_hash = chia::clvm_utils::tree_hash(&alloc, ptr);
        Ok(Self {
            mod_hash,
            mod_bytes: bytes,
        })
    }

    /// Create a PuzzleModule from a hex string (with optional whitespace)
    pub fn from_hex(hex_str: &str) -> Result<Self, DriverError> {
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| DriverError::PuzzleParse(format!("Invalid hex: {}", e)))?;
        Self::new(bytes)
    }

    /// Get the module hash (uncurried puzzle hash)
    pub fn mod_hash(&self) -> TreeHash {
        self.mod_hash
    }

    /// Get the raw puzzle bytes
    pub fn mod_bytes(&self) -> &[u8] {
        &self.mod_bytes
    }

    /// Build a curried puzzle in the spend context.
    ///
    /// The args type should have `#[clvm(curry)]` attribute for proper serialization.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// #[derive(ToClvm)]
    /// #[clvm(curry)]
    /// struct MyCurryArgs { pub hash: Bytes32 }
    ///
    /// let curried = puzzle.curry_puzzle(ctx, MyCurryArgs { hash })?;
    /// ```
    pub fn curry_puzzle<A>(&self, ctx: &mut SpendContext, args: A) -> Result<NodePtr, DriverError>
    where
        A: ToClvm<Allocator>,
    {
        let mod_ptr = ctx
            .puzzle(self.mod_hash, &self.mod_bytes)
            .map_err(|e| DriverError::PuzzleLoad(format!("{:?}", e)))?;

        ctx.alloc(&CurriedProgram {
            program: mod_ptr,
            args,
        })
        .map_err(|e| DriverError::Alloc(format!("{:?}", e)))
    }
}

impl std::fmt::Debug for PuzzleModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PuzzleModule")
            .field("mod_hash", &hex::encode(self.mod_hash.to_bytes()))
            .field("mod_bytes_len", &self.mod_bytes.len())
            .finish()
    }
}
