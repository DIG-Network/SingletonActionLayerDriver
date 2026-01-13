//! Action Layer configuration and spend building
//!
//! Provides utilities for constructing action layer spends following the CHIP-0050 pattern.

use std::marker::PhantomData;

use chia::protocol::Bytes32;
use chia_wallet_sdk::driver::{ActionLayer, ActionLayerSolution, Finalizer, Layer, Spend, SpendContext};
use chia_wallet_sdk::types::puzzles::{ActionLayerArgs, DefaultFinalizer2ndCurryArgs};
use chia_wallet_sdk::types::MerkleTree;
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::{ToTreeHash, TreeHash};
use clvmr::{Allocator, NodePtr};

use crate::DriverError;

/// Configuration for building action layer spends.
///
/// Generic over the state type `S`, which must implement proper CLVM traits.
/// The state should be a proper cons cell (use `#[clvm(list)]` with `#[clvm(rest)]` on last field).
///
/// # Example
///
/// ```rust,ignore
/// // State must be a cons cell
/// #[derive(Debug, Clone, ToClvm, FromClvm)]
/// #[clvm(list)]
/// pub struct MyState {
///     pub counter: u64,
///     #[clvm(rest)]
///     pub data: Bytes32,
/// }
///
/// let config = ActionLayerConfig::<MyState>::new(action_hashes, hint);
/// let inner_hash = config.inner_puzzle_hash(&state);
/// ```
pub struct ActionLayerConfig<S> {
    action_hashes: Vec<Bytes32>,
    merkle_tree: MerkleTree,
    hint: Bytes32,
    _phantom: PhantomData<S>,
}

impl<S> ActionLayerConfig<S>
where
    S: Clone + ToClvm<Allocator> + FromClvm<Allocator> + ToTreeHash,
{
    /// Create a new action layer configuration.
    ///
    /// # Arguments
    /// * `action_hashes` - The curried puzzle hashes for each action
    /// * `hint` - The hint for the default finalizer
    pub fn new(action_hashes: Vec<Bytes32>, hint: Bytes32) -> Self {
        let merkle_tree = MerkleTree::new(&action_hashes);
        Self {
            action_hashes,
            merkle_tree,
            hint,
            _phantom: PhantomData,
        }
    }

    /// Get the action hashes
    pub fn action_hashes(&self) -> &[Bytes32] {
        &self.action_hashes
    }

    /// Get the merkle root of action hashes
    pub fn merkle_root(&self) -> Bytes32 {
        self.merkle_tree.root()
    }

    /// Get the hint
    pub fn hint(&self) -> Bytes32 {
        self.hint
    }

    /// Compute the action layer inner puzzle hash for a given state.
    ///
    /// This uses:
    /// - DefaultFinalizer2ndCurryArgs for the finalizer hash
    /// - The merkle root of action hashes
    /// - The state tree hash
    pub fn inner_puzzle_hash(&self, state: &S) -> TreeHash {
        // CRITICAL: Use 2nd curry for finalizer (not 1st)
        let finalizer_hash = DefaultFinalizer2ndCurryArgs::curry_tree_hash(self.hint);

        ActionLayerArgs::<TreeHash, TreeHash>::curry_tree_hash(
            finalizer_hash,
            self.merkle_tree.root(),
            state.tree_hash(),
        )
    }

    /// Create an ActionLayer instance for spending
    pub fn create_action_layer(&self, state: S) -> ActionLayer<S> {
        ActionLayer::from_action_puzzle_hashes(
            &self.action_hashes,
            state,
            Finalizer::Default { hint: self.hint },
        )
    }

    /// Build an action layer spend.
    ///
    /// Returns the inner puzzle and solution NodePtrs.
    ///
    /// # Arguments
    /// * `ctx` - The spend context
    /// * `state` - The current state
    /// * `action_index` - Which action to invoke (index into action_hashes)
    /// * `action_puzzle` - The curried action puzzle (use PuzzleModule::curry_puzzle)
    /// * `action_solution` - The action solution NodePtr
    pub fn build_action_spend(
        &self,
        ctx: &mut SpendContext,
        state: S,
        action_index: usize,
        action_puzzle: NodePtr,
        action_solution: NodePtr,
    ) -> Result<(NodePtr, NodePtr), DriverError> {
        // Validate action index
        if action_index >= self.action_hashes.len() {
            return Err(DriverError::InvalidActionIndex {
                index: action_index,
                count: self.action_hashes.len(),
            });
        }

        let action_hash = self.action_hashes[action_index];

        // Create action layer
        let action_layer = self.create_action_layer(state);

        // Build action layer inner puzzle
        let inner_puzzle = action_layer
            .construct_puzzle(ctx)
            .map_err(|e| DriverError::ActionLayer(format!("construct_puzzle: {:?}", e)))?;

        // CRITICAL: Use MerkleTree::proof directly (not ActionLayer::get_proofs)
        let merkle_proof = self
            .merkle_tree
            .proof(action_hash)
            .ok_or(DriverError::MerkleProofNotFound)?;

        // Build action layer solution
        let action_layer_solution = ActionLayerSolution {
            proofs: vec![merkle_proof],
            action_spends: vec![Spend::new(action_puzzle, action_solution)],
            finalizer_solution: NodePtr::NIL,
        };

        let inner_solution = action_layer
            .construct_solution(ctx, action_layer_solution)
            .map_err(|e| DriverError::ActionLayer(format!("construct_solution: {:?}", e)))?;

        Ok((inner_puzzle, inner_solution))
    }
}

impl<S> Clone for ActionLayerConfig<S> {
    fn clone(&self) -> Self {
        Self {
            action_hashes: self.action_hashes.clone(),
            merkle_tree: MerkleTree::new(&self.action_hashes),
            hint: self.hint,
            _phantom: PhantomData,
        }
    }
}

impl<S> std::fmt::Debug for ActionLayerConfig<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionLayerConfig")
            .field("action_count", &self.action_hashes.len())
            .field("merkle_root", &hex::encode(self.merkle_tree.root()))
            .field("hint", &hex::encode(self.hint))
            .finish()
    }
}
