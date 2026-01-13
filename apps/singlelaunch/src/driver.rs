//! Driver code for Action Layer spend bundle construction
//!
//! This module provides application-specific types and helpers that wrap the
//! generic action-layer-driver crate for the two-action singleton pattern.

use chia::protocol::{Bytes32, Coin};
use chia::puzzles::Proof;

use chia_wallet_sdk::driver::SpendContext;
use chia_wallet_sdk::types::Conditions;

use clvm_traits::{ToClvm, FromClvm};
use clvm_utils::{CurriedProgram, ToTreeHash, TreeHash};

// Import from action-layer-driver crate
use action_layer_driver::{
    ActionLayerConfig, PuzzleModule,
    launch_singleton, spawn_child_singleton,
    build_singleton_puzzle, build_singleton_solution, create_singleton_coin_spend,
    singleton_puzzle_hash, child_singleton_puzzle_hash, expected_child_launcher_id,
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
pub struct EmitChildActionSolution {
    pub my_singleton_coin_id: Bytes32,
    #[clvm(rest)]
    pub child_singleton_puzzle_hash: Bytes32,
}

/// Curried args for emit_child_action puzzle
#[derive(Debug, Clone, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct EmitChildActionCurriedArgs {
    pub child_inner_puzzle_hash: Bytes32,
}

impl EmitChildActionCurriedArgs {
    pub fn curry_tree_hash(mod_hash: TreeHash, child_inner_puzzle_hash: Bytes32) -> TreeHash {
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

    pub fn increment(&self) -> Self {
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

pub fn child_inner_puzzle_hash() -> TreeHash {
    get_child_puzzle_module().mod_hash()
}

pub fn child_inner_puzzle_2_hash() -> TreeHash {
    get_child_puzzle_2_module().mod_hash()
}

/// Compute the curried emit_child_action puzzle hash for a given child inner puzzle
pub fn emit_child_action_curried_hash(child_inner: Bytes32) -> TreeHash {
    let module = get_emit_child_action_module();
    EmitChildActionCurriedArgs::curry_tree_hash(module.mod_hash(), child_inner)
}

// ============================================================================
// Two-Action Configuration
// ============================================================================

/// Configuration for a two-action layer
pub struct TwoActionConfig {
    pub hint: Bytes32,
    pub child_inner_1: Bytes32,
    pub child_inner_2: Bytes32,
    action_layer: ActionLayerConfig<ActionState>,
}

impl TwoActionConfig {
    pub fn new(hint: Bytes32) -> Self {
        let child_inner_1: Bytes32 = child_inner_puzzle_hash().into();
        let child_inner_2: Bytes32 = child_inner_puzzle_2_hash().into();

        let action_hashes = vec![
            emit_child_action_curried_hash(child_inner_1).into(),
            emit_child_action_curried_hash(child_inner_2).into(),
        ];

        Self {
            hint,
            child_inner_1,
            child_inner_2,
            action_layer: ActionLayerConfig::new(action_hashes, hint),
        }
    }

    pub fn action1_hash(&self) -> Bytes32 {
        self.action_layer.action_hashes()[0]
    }

    pub fn action2_hash(&self) -> Bytes32 {
        self.action_layer.action_hashes()[1]
    }

    pub fn action_hashes(&self) -> &[Bytes32] {
        self.action_layer.action_hashes()
    }

    /// Compute the action layer inner puzzle hash for a given state
    pub fn compute_inner_hash(&self, state: ActionState) -> TreeHash {
        self.action_layer.inner_puzzle_hash(&state)
    }
}

// ============================================================================
// Spend Bundle Builders
// ============================================================================

/// Create a singleton with a two-action layer
pub fn create_singleton_spend(
    ctx: &mut SpendContext,
    funding_coin: &Coin,
    config: &TwoActionConfig,
    state: ActionState,
    singleton_amount: u64,
) -> anyhow::Result<(Bytes32, Coin, Conditions)> {
    let inner_hash: Bytes32 = config.compute_inner_hash(state).into();

    let result = launch_singleton(ctx, funding_coin, inner_hash, singleton_amount)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok((result.launcher_id, result.singleton_coin, result.launcher_conditions))
}

/// Result of emitting a child singleton
pub struct EmitChildResult {
    pub child_launcher_id: Bytes32,
    pub child_singleton: Coin,
    pub new_parent_coin: Coin,
    pub new_state: ActionState,
}

/// Build a spend to emit a child singleton via an action
pub fn build_emit_child_spend(
    ctx: &mut SpendContext,
    singleton_coin: &Coin,
    launcher_id: Bytes32,
    config: &TwoActionConfig,
    state: ActionState,
    proof: Proof,
    use_action_1: bool,
) -> anyhow::Result<EmitChildResult> {
    // Determine which action and child inner puzzle to use
    let (action_index, child_inner_hash, child_inner_tree_hash) = if use_action_1 {
        (0, config.child_inner_1, child_inner_puzzle_hash())
    } else {
        (1, config.child_inner_2, child_inner_puzzle_2_hash())
    };

    // Compute child launcher ID
    let child_launcher_id = expected_child_launcher_id(singleton_coin.coin_id());

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

    // Build action layer spend using the crate
    let (inner_puzzle, inner_solution) = config.action_layer.build_action_spend(
        ctx,
        state,
        action_index,
        action_puzzle,
        action_solution_ptr,
    ).map_err(|e| anyhow::anyhow!("{}", e))?;

    // Build singleton puzzle and solution
    let singleton_puzzle = build_singleton_puzzle(ctx, launcher_id, inner_puzzle)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let singleton_solution = build_singleton_solution(ctx, proof, singleton_coin.amount, inner_solution)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Insert singleton spend
    create_singleton_coin_spend(ctx, singleton_coin, singleton_puzzle, singleton_solution)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Spawn child singleton (ephemeral launcher)
    let child_result = spawn_child_singleton(ctx, singleton_coin.coin_id(), child_inner_tree_hash)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Compute new state and parent coin
    let new_state = state.increment();
    let new_inner_hash = config.compute_inner_hash(new_state);
    let new_singleton_puzzle_hash = singleton_puzzle_hash(launcher_id, new_inner_hash);
    let new_parent_coin = Coin::new(
        singleton_coin.coin_id(),
        new_singleton_puzzle_hash,
        singleton_coin.amount,
    );

    Ok(EmitChildResult {
        child_launcher_id: child_result.child_launcher_id,
        child_singleton: child_result.child_singleton,
        new_parent_coin,
        new_state,
    })
}

// Re-export proof creation functions from the crate with original names
pub use action_layer_driver::create_eve_proof;
pub use action_layer_driver::create_lineage_proof;
