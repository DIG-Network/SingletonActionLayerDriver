//! SingletonDriver - Core driver for Action Layer singletons

use chia::protocol::{Bytes32, Coin, CoinSpend};
use chia::puzzles::singleton::{SingletonArgs, SingletonSolution, SingletonStruct};
use chia_wallet_sdk::driver::{Launcher, SpendContext};
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::{CurriedProgram, ToTreeHash, TreeHash};
use clvmr::{Allocator, NodePtr};

use crate::action_layer::ActionLayerConfig;
use crate::error::DriverError;
use crate::singleton::types::{LaunchResult, SingletonCoin, SingletonLineage};

/// Singleton launcher puzzle hash (standard)
pub const SINGLETON_LAUNCHER_PUZZLE_HASH: [u8; 32] =
    hex_literal::hex!("eff07522495060c066f66f32acc2a77e3a3e737aca8baea4d1a64ea4cdc13da9");

/// Core driver for Action Layer singletons.
///
/// Generic over the state type `S`. Handles common singleton operations:
/// - Launching
/// - Building action spends
/// - State/lineage tracking
/// - Proof generation
///
/// Specific singleton implementations (NetworkSingleton, CollateralSingleton, etc.)
/// wrap this driver and expose typed action methods.
pub struct SingletonDriver<S> {
    /// On-chain singleton info (None if not yet launched)
    singleton: Option<SingletonCoin>,

    /// Current state
    state: S,

    /// Action layer configuration
    action_config: ActionLayerConfig<S>,

    /// Hint for the default finalizer
    hint: Bytes32,
}

impl<S> SingletonDriver<S>
where
    S: Clone + ToClvm<Allocator> + FromClvm<Allocator> + ToTreeHash,
{
    // ========================================================================
    // Construction
    // ========================================================================

    /// Create a driver for a new singleton (not yet launched)
    pub fn new(action_hashes: Vec<Bytes32>, hint: Bytes32, initial_state: S) -> Self {
        let action_config = ActionLayerConfig::new(action_hashes, hint);
        Self {
            singleton: None,
            state: initial_state,
            action_config,
            hint,
        }
    }

    /// Create a driver for an existing on-chain singleton
    pub fn from_coin(
        singleton: SingletonCoin,
        state: S,
        action_hashes: Vec<Bytes32>,
        hint: Bytes32,
    ) -> Self {
        let action_config = ActionLayerConfig::new(action_hashes, hint);
        Self {
            singleton: Some(singleton),
            state,
            action_config,
            hint,
        }
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Get the launcher ID (None if not launched)
    pub fn launcher_id(&self) -> Option<Bytes32> {
        self.singleton.as_ref().map(|s| s.launcher_id)
    }

    /// Get the current coin (None if not launched or melted)
    pub fn current_coin(&self) -> Option<&Coin> {
        self.singleton.as_ref().map(|s| &s.coin)
    }

    /// Get the current state
    pub fn state(&self) -> &S {
        &self.state
    }

    /// Get mutable reference to state (for direct updates)
    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }

    /// Check if the singleton has been launched
    pub fn is_launched(&self) -> bool {
        self.singleton.is_some()
    }

    /// Get the hint
    pub fn hint(&self) -> Bytes32 {
        self.hint
    }

    /// Get the action layer config
    pub fn action_config(&self) -> &ActionLayerConfig<S> {
        &self.action_config
    }

    /// Compute the inner puzzle hash for the current state
    pub fn inner_puzzle_hash(&self) -> TreeHash {
        self.action_config.inner_puzzle_hash(&self.state)
    }

    /// Compute the inner puzzle hash for a given state
    pub fn inner_puzzle_hash_for_state(&self, state: &S) -> TreeHash {
        self.action_config.inner_puzzle_hash(state)
    }

    /// Compute the full singleton puzzle hash (None if not launched)
    pub fn singleton_puzzle_hash(&self) -> Option<TreeHash> {
        self.launcher_id().map(|launcher_id| {
            SingletonArgs::curry_tree_hash(launcher_id, self.inner_puzzle_hash())
        })
    }

    /// Compute singleton puzzle hash for a given state
    pub fn singleton_puzzle_hash_for_state(&self, state: &S) -> Option<TreeHash> {
        self.launcher_id().map(|launcher_id| {
            SingletonArgs::curry_tree_hash(launcher_id, self.inner_puzzle_hash_for_state(state))
        })
    }

    /// Get the proof for the next spend (None if not launched)
    pub fn proof(&self) -> Option<chia::puzzles::Proof> {
        self.singleton.as_ref().map(|s| s.proof())
    }

    // ========================================================================
    // Action Hash Management
    // ========================================================================

    /// Update action hashes (needed after launch when network_id becomes known)
    pub fn update_action_hashes(&mut self, action_hashes: Vec<Bytes32>) {
        self.action_config = ActionLayerConfig::new(action_hashes, self.hint);
    }

    // ========================================================================
    // Lifecycle Operations
    // ========================================================================

    /// Launch the singleton
    ///
    /// Creates the launcher spend in the context. Returns the launcher ID and
    /// conditions to be included in the funding coin spend.
    pub fn launch(
        &mut self,
        ctx: &mut SpendContext,
        funding_coin: &Coin,
        amount: u64,
    ) -> Result<LaunchResult, DriverError> {
        if self.is_launched() {
            return Err(DriverError::AlreadyLaunched);
        }

        let inner_hash: Bytes32 = self.inner_puzzle_hash().into();

        let launcher = Launcher::new(funding_coin.coin_id(), amount);
        let launcher_id = launcher.coin().coin_id();

        let (launcher_conditions, singleton_coin) = launcher
            .spend(ctx, inner_hash, ())
            .map_err(|e| DriverError::Launcher(format!("{:?}", e)))?;

        // Update internal state
        let lineage = SingletonLineage::eve(funding_coin.coin_id(), amount);
        self.singleton = Some(SingletonCoin::new(launcher_id, singleton_coin, lineage));

        Ok(LaunchResult {
            launcher_id,
            coin: singleton_coin,
            conditions: launcher_conditions,
        })
    }

    /// Build an action spend.
    ///
    /// Adds the singleton spend to the context. Does NOT update internal state -
    /// call `apply_spend()` after the transaction confirms.
    ///
    /// # Arguments
    /// * `ctx` - Spend context
    /// * `action_index` - Index of the action in the merkle tree
    /// * `action_puzzle` - The curried action puzzle (NodePtr)
    /// * `action_solution` - The action solution (NodePtr)
    pub fn build_action_spend(
        &self,
        ctx: &mut SpendContext,
        action_index: usize,
        action_puzzle: NodePtr,
        action_solution: NodePtr,
    ) -> Result<(), DriverError> {
        let singleton = self.singleton.as_ref().ok_or(DriverError::NotLaunched)?;

        // Build action layer spend (inner puzzle + solution)
        let (inner_puzzle, inner_solution) = self.action_config.build_action_spend(
            ctx,
            self.state.clone(),
            action_index,
            action_puzzle,
            action_solution,
        )?;

        // Build singleton puzzle
        let singleton_puzzle = self.build_singleton_puzzle(ctx, inner_puzzle)?;

        // Build singleton solution
        let singleton_solution = self.build_singleton_solution(
            ctx,
            singleton.proof(),
            singleton.coin.amount,
            inner_solution,
        )?;

        // Create and insert coin spend
        let puzzle_reveal = ctx
            .serialize(&singleton_puzzle)
            .map_err(|e| DriverError::Serialize(format!("{:?}", e)))?;
        let solution = ctx
            .serialize(&singleton_solution)
            .map_err(|e| DriverError::Serialize(format!("{:?}", e)))?;

        let coin_spend = CoinSpend::new(singleton.coin, puzzle_reveal, solution);
        ctx.insert(coin_spend);

        Ok(())
    }

    /// Update internal state after a spend confirms.
    ///
    /// Call this after the transaction is confirmed on chain.
    pub fn apply_spend(&mut self, new_state: S) {
        if let Some(singleton) = &self.singleton {
            let launcher_id = singleton.launcher_id;
            let old_coin = singleton.coin;
            let old_inner_hash = self.inner_puzzle_hash();

            // Update state first (needed for new puzzle hash calculation)
            self.state = new_state;

            // Compute new coin
            let new_puzzle_hash: Bytes32 = self
                .singleton_puzzle_hash()
                .expect("singleton should exist")
                .into();
            let new_coin = Coin::new(old_coin.coin_id(), new_puzzle_hash, old_coin.amount);

            // Update lineage
            let new_lineage = SingletonLineage::lineage(old_coin, old_inner_hash);

            self.singleton = Some(SingletonCoin::new(launcher_id, new_coin, new_lineage));
        }
    }

    /// Mark the singleton as melted (destroyed).
    ///
    /// Call this after a melt action (like withdraw) confirms.
    pub fn mark_melted(&mut self) {
        self.singleton = None;
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    /// Compute the expected new coin after a spend with given new state
    pub fn expected_new_coin(&self, new_state: &S) -> Option<Coin> {
        let singleton = self.singleton.as_ref()?;
        let new_inner_hash = self.inner_puzzle_hash_for_state(new_state);
        let new_puzzle_hash: Bytes32 =
            SingletonArgs::curry_tree_hash(singleton.launcher_id, new_inner_hash).into();
        Some(Coin::new(
            singleton.coin.coin_id(),
            new_puzzle_hash,
            singleton.coin.amount,
        ))
    }

    /// Compute the expected child launcher ID for a child singleton
    /// emitted by the current singleton
    pub fn expected_child_launcher_id(&self) -> Option<Bytes32> {
        let singleton = self.singleton.as_ref()?;
        let child_launcher_coin = Coin::new(
            singleton.coin.coin_id(),
            Bytes32::new(SINGLETON_LAUNCHER_PUZZLE_HASH),
            0,
        );
        Some(child_launcher_coin.coin_id())
    }

    /// Build the singleton puzzle (internal helper)
    fn build_singleton_puzzle(
        &self,
        ctx: &mut SpendContext,
        inner_puzzle: NodePtr,
    ) -> Result<NodePtr, DriverError> {
        let launcher_id = self.launcher_id().ok_or(DriverError::NotLaunched)?;

        let singleton_mod_hash = TreeHash::new(chia_puzzles::SINGLETON_TOP_LAYER_V1_1_HASH);
        let singleton_ptr = ctx
            .puzzle(singleton_mod_hash, &chia_puzzles::SINGLETON_TOP_LAYER_V1_1)
            .map_err(|e| DriverError::PuzzleLoad(format!("singleton: {:?}", e)))?;

        ctx.alloc(&CurriedProgram {
            program: singleton_ptr,
            args: SingletonArgs {
                singleton_struct: SingletonStruct::new(launcher_id),
                inner_puzzle,
            },
        })
        .map_err(|e| DriverError::Alloc(format!("singleton curry: {:?}", e)))
    }

    /// Build the singleton solution (internal helper)
    fn build_singleton_solution(
        &self,
        ctx: &mut SpendContext,
        proof: chia::puzzles::Proof,
        amount: u64,
        inner_solution: NodePtr,
    ) -> Result<NodePtr, DriverError> {
        ctx.alloc(&SingletonSolution {
            lineage_proof: proof,
            amount,
            inner_solution,
        })
        .map_err(|e| DriverError::Alloc(format!("singleton solution: {:?}", e)))
    }
}

impl<S: std::fmt::Debug> std::fmt::Debug for SingletonDriver<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingletonDriver")
            .field(
                "launcher_id",
                &self.singleton.as_ref().map(|s| hex::encode(s.launcher_id)),
            )
            .field("is_launched", &self.singleton.is_some())
            .field("state", &self.state)
            .finish()
    }
}
