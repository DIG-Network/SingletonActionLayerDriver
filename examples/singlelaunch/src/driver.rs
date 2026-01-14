//! Driver code for Action Layer spend bundle construction
//!
//! This module provides application-specific types and helpers that wrap the
//! generic SingletonDriver for the two-action singleton pattern.

use chia::protocol::{Bytes32, Coin};
use chia_wallet_sdk::driver::SpendContext;

use clvm_traits::{ToClvm, FromClvm};
use clvm_utils::{CurriedProgram, ToTreeHash, TreeHash};

// Import from action-layer-driver crate
use action_layer_driver::{
    PuzzleModule, SingletonDriver, LaunchResult,
    spawn_child_singleton, child_singleton_puzzle_hash,
};

// ============================================================================
// Constants
// ============================================================================

/// The compiled emit_child_action.rue - curried with child_inner_puzzle_hash
const EMIT_CHILD_ACTION_HEX: &str = include_str!("../../../puzzles/output/emit_child_action.clvm.hex");

/// The compiled child_inner_puzzle.rue (child type 1)
const CHILD_PUZZLE_HEX: &str = include_str!("../../../puzzles/output/child_inner_puzzle.clvm.hex");

/// The compiled child_inner_puzzle_2.rue (child type 2)
const CHILD_PUZZLE_2_HEX: &str = include_str!("../../../puzzles/output/child_inner_puzzle_2.clvm.hex");

// ============================================================================
// Application-Specific CLVM Types
// ============================================================================

/// Solution for emit_child_action puzzle
#[derive(Debug, Clone, ToClvm, FromClvm)]
#[clvm(list)]
struct EmitChildActionSolution {
    my_singleton_coin_id: Bytes32,
    #[clvm(rest)]
    child_singleton_puzzle_hash: Bytes32,
}

/// Curried args for emit_child_action puzzle
#[derive(Debug, Clone, ToClvm, FromClvm)]
#[clvm(curry)]
struct EmitChildActionCurriedArgs {
    child_inner_puzzle_hash: Bytes32,
}

impl EmitChildActionCurriedArgs {
    fn curry_tree_hash(mod_hash: TreeHash, child_inner_puzzle_hash: Bytes32) -> TreeHash {
        CurriedProgram {
            program: mod_hash,
            args: EmitChildActionCurriedArgs { child_inner_puzzle_hash },
        }.tree_hash()
    }
}

/// State for action layer - must be a proper cons cell (two fields)
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct ActionState {
    pub counter: u64,
    #[clvm(rest)]
    pub marker: u64,
}

impl ActionState {
    pub fn new(counter: u64, marker: u64) -> Self {
        Self { counter, marker }
    }

    fn increment(&self) -> Self {
        Self {
            counter: self.counter + 1,
            marker: self.marker,
        }
    }
}

// ============================================================================
// Puzzle Loading
// ============================================================================

fn get_emit_child_action_module() -> PuzzleModule {
    PuzzleModule::from_hex(EMIT_CHILD_ACTION_HEX).expect("valid emit_child_action puzzle")
}

fn get_child_puzzle_module() -> PuzzleModule {
    PuzzleModule::from_hex(CHILD_PUZZLE_HEX).expect("valid child_puzzle")
}

fn get_child_puzzle_2_module() -> PuzzleModule {
    PuzzleModule::from_hex(CHILD_PUZZLE_2_HEX).expect("valid child_puzzle_2")
}

fn child_inner_puzzle_hash() -> TreeHash {
    get_child_puzzle_module().mod_hash()
}

fn child_inner_puzzle_2_hash() -> TreeHash {
    get_child_puzzle_2_module().mod_hash()
}

fn emit_child_action_curried_hash(child_inner: Bytes32) -> TreeHash {
    let module = get_emit_child_action_module();
    EmitChildActionCurriedArgs::curry_tree_hash(module.mod_hash(), child_inner)
}

// ============================================================================
// Two-Action Singleton Driver
// ============================================================================

/// High-level driver for a two-action singleton.
///
/// Wraps SingletonDriver<ActionState> and provides typed methods
/// for the two emit_child actions.
pub struct TwoActionSingleton {
    driver: SingletonDriver<ActionState>,
    child_inner_1: Bytes32,
    child_inner_2: Bytes32,
}

impl TwoActionSingleton {
    /// Create a new driver for a two-action singleton (not yet launched)
    pub fn new(hint: Bytes32, initial_state: ActionState) -> Self {
        let child_inner_1: Bytes32 = child_inner_puzzle_hash().into();
        let child_inner_2: Bytes32 = child_inner_puzzle_2_hash().into();

        let action_hashes = vec![
            emit_child_action_curried_hash(child_inner_1).into(),
            emit_child_action_curried_hash(child_inner_2).into(),
        ];

        Self {
            driver: SingletonDriver::new(action_hashes, hint, initial_state),
            child_inner_1,
            child_inner_2,
        }
    }

    /// Get child inner puzzle 1 hash
    pub fn child_inner_1(&self) -> Bytes32 {
        self.child_inner_1
    }

    /// Get child inner puzzle 2 hash
    pub fn child_inner_2(&self) -> Bytes32 {
        self.child_inner_2
    }

    /// Launch the singleton
    pub fn launch(
        &mut self,
        ctx: &mut SpendContext,
        funding_coin: &Coin,
        amount: u64,
    ) -> anyhow::Result<LaunchResult> {
        self.driver
            .launch(ctx, funding_coin, amount)
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    /// Emit a child singleton via action 1 (child_inner_puzzle)
    pub fn emit_child_1(
        &mut self,
        ctx: &mut SpendContext,
    ) -> anyhow::Result<EmitChildResult> {
        self.emit_child_impl(ctx, 0, self.child_inner_1, child_inner_puzzle_hash())
    }

    /// Emit a child singleton via action 2 (child_inner_puzzle_2)
    pub fn emit_child_2(
        &mut self,
        ctx: &mut SpendContext,
    ) -> anyhow::Result<EmitChildResult> {
        self.emit_child_impl(ctx, 1, self.child_inner_2, child_inner_puzzle_2_hash())
    }

    /// Internal implementation for emit_child actions
    fn emit_child_impl(
        &mut self,
        ctx: &mut SpendContext,
        action_index: usize,
        child_inner_hash: Bytes32,
        child_inner_tree_hash: TreeHash,
    ) -> anyhow::Result<EmitChildResult> {
        let singleton_coin = self.driver.current_coin()
            .ok_or_else(|| anyhow::anyhow!("Singleton not launched"))?
            .clone();

        // Compute child launcher ID from current singleton
        let child_launcher_id = self.driver.expected_child_launcher_id()
            .ok_or_else(|| anyhow::anyhow!("Could not compute child launcher ID"))?;

        // Child singleton puzzle hash
        let child_singleton_hash = child_singleton_puzzle_hash(child_launcher_id, child_inner_tree_hash);

        // Build curried action puzzle
        let emit_module = get_emit_child_action_module();
        let action_puzzle = emit_module.curry_puzzle(
            ctx,
            EmitChildActionCurriedArgs { child_inner_puzzle_hash: child_inner_hash },
        ).map_err(|e| anyhow::anyhow!("{}", e))?;

        // Build action solution
        let action_solution = EmitChildActionSolution {
            my_singleton_coin_id: singleton_coin.coin_id(),
            child_singleton_puzzle_hash: child_singleton_hash,
        };
        let action_solution_ptr = ctx.alloc(&action_solution)
            .map_err(|e| anyhow::anyhow!("Failed to alloc action solution: {:?}", e))?;

        // Build singleton spend using the driver
        self.driver.build_action_spend(ctx, action_index, action_puzzle, action_solution_ptr)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        // Spawn child singleton (ephemeral launcher)
        let child_result = spawn_child_singleton(ctx, singleton_coin.coin_id(), child_inner_tree_hash)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        // Compute new state
        let new_state = self.driver.state().increment();

        // Compute new parent coin (for tracking before confirmation)
        let new_parent_coin = self.driver.expected_new_coin(&new_state)
            .ok_or_else(|| anyhow::anyhow!("Could not compute new parent coin"))?;

        Ok(EmitChildResult {
            child_launcher_id: child_result.child_launcher_id,
            child_singleton: child_result.child_singleton,
            new_parent_coin,
            new_state,
        })
    }

    /// Apply the state change after a spend confirms
    pub fn apply_spend(&mut self, new_state: ActionState) {
        self.driver.apply_spend(new_state);
    }
}

// ============================================================================
// Result Types
// ============================================================================

/// Result of emitting a child singleton
pub struct EmitChildResult {
    pub child_launcher_id: Bytes32,
    pub child_singleton: Coin,
    pub new_parent_coin: Coin,
    pub new_state: ActionState,
}
