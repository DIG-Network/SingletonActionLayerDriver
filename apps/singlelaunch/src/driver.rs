//! Driver code for Action Layer spend bundle construction
//!
//! This module handles all CLVM/puzzle logic for the two-action pattern:
//! - Puzzle loading and hashing
//! - Action layer construction
//! - Spend bundle building for singleton and child emission

use chia::protocol::{Bytes32, Coin, CoinSpend};
use chia::puzzles::{Proof, EveProof, LineageProof};
use chia::puzzles::singleton::{SingletonArgs, SingletonSolution, SingletonStruct};

use chia_wallet_sdk::driver::{SpendContext, Launcher, Spend, Layer};
use chia_wallet_sdk::driver::{ActionLayer, ActionLayerSolution, Finalizer};
use chia_wallet_sdk::types::{Conditions, MerkleTree};
use chia_wallet_sdk::types::puzzles::{ActionLayerArgs, DefaultFinalizer2ndCurryArgs};

use clvm_traits::{ToClvm, FromClvm};
use clvm_utils::{CurriedProgram, ToTreeHash, TreeHash};
use clvmr::{Allocator, NodePtr};
use clvmr::serde::node_from_bytes;

// ============================================================================
// Constants
// ============================================================================

/// The compiled emit_child_action.rue - curried with child_inner_puzzle_hash
const EMIT_CHILD_ACTION_HEX: &str = include_str!("../../../puzzles/output/emit_child_action.clvm.hex");

/// The compiled child_inner_puzzle.rue (child type 1)
const CHILD_PUZZLE_HEX: &str = include_str!("../../../puzzles/output/child_inner_puzzle.clvm.hex");

/// The compiled child_inner_puzzle_2.rue (child type 2)
const CHILD_PUZZLE_2_HEX: &str = include_str!("../../../puzzles/output/child_inner_puzzle_2.clvm.hex");

/// Singleton launcher puzzle hash
pub const SINGLETON_LAUNCHER_PUZZLE_HASH: [u8; 32] = hex_literal::hex!(
    "eff07522495060c066f66f32acc2a77e3a3e737aca8baea4d1a64ea4cdc13da9"
);

// ============================================================================
// CLVM Types
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
// Puzzle Loading & Hashing
// ============================================================================

pub fn get_emit_child_action_bytes() -> Vec<u8> {
    hex::decode(EMIT_CHILD_ACTION_HEX.trim()).expect("valid hex")
}

pub fn get_child_puzzle_bytes() -> Vec<u8> {
    hex::decode(CHILD_PUZZLE_HEX.trim()).expect("valid hex")
}

pub fn get_child_puzzle_2_bytes() -> Vec<u8> {
    hex::decode(CHILD_PUZZLE_2_HEX.trim()).expect("valid hex")
}

pub fn emit_child_action_mod_hash() -> TreeHash {
    let bytes = get_emit_child_action_bytes();
    let mut alloc = Allocator::new();
    let ptr = node_from_bytes(&mut alloc, &bytes).expect("valid puzzle");
    chia::clvm_utils::tree_hash(&alloc, ptr)
}

pub fn child_inner_puzzle_hash() -> TreeHash {
    let bytes = get_child_puzzle_bytes();
    let mut alloc = Allocator::new();
    let ptr = node_from_bytes(&mut alloc, &bytes).expect("valid puzzle");
    chia::clvm_utils::tree_hash(&alloc, ptr)
}

pub fn child_inner_puzzle_2_hash() -> TreeHash {
    let bytes = get_child_puzzle_2_bytes();
    let mut alloc = Allocator::new();
    let ptr = node_from_bytes(&mut alloc, &bytes).expect("valid puzzle");
    chia::clvm_utils::tree_hash(&alloc, ptr)
}

/// Compute the curried emit_child_action puzzle hash for a given child inner puzzle
pub fn emit_child_action_curried_hash(child_inner: Bytes32) -> TreeHash {
    EmitChildActionCurriedArgs::curry_tree_hash(emit_child_action_mod_hash(), child_inner)
}

// ============================================================================
// Action Layer Construction
// ============================================================================

/// Configuration for a two-action layer
pub struct TwoActionConfig {
    pub hint: Bytes32,
    pub child_inner_1: Bytes32,
    pub child_inner_2: Bytes32,
}

impl TwoActionConfig {
    pub fn new(hint: Bytes32) -> Self {
        Self {
            hint,
            child_inner_1: child_inner_puzzle_hash().into(),
            child_inner_2: child_inner_puzzle_2_hash().into(),
        }
    }

    pub fn action1_hash(&self) -> Bytes32 {
        emit_child_action_curried_hash(self.child_inner_1).into()
    }

    pub fn action2_hash(&self) -> Bytes32 {
        emit_child_action_curried_hash(self.child_inner_2).into()
    }

    pub fn action_hashes(&self) -> Vec<Bytes32> {
        vec![self.action1_hash(), self.action2_hash()]
    }

    /// Compute the action layer inner puzzle hash for a given state
    pub fn compute_inner_hash(&self, state: ActionState) -> TreeHash {
        let action_hashes = self.action_hashes();
        let merkle_tree = MerkleTree::new(&action_hashes);

        // CRITICAL: Use 2nd curry for finalizer (not 1st)
        let finalizer_hash = DefaultFinalizer2ndCurryArgs::curry_tree_hash(self.hint);

        ActionLayerArgs::<TreeHash, TreeHash>::curry_tree_hash(
            finalizer_hash,
            merkle_tree.root(),
            state.tree_hash(),
        )
    }

    /// Create an ActionLayer for spending
    pub fn create_action_layer(&self, state: ActionState) -> ActionLayer<ActionState> {
        ActionLayer::from_action_puzzle_hashes(
            &self.action_hashes(),
            state,
            Finalizer::Default { hint: self.hint },
        )
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

    let launcher = Launcher::new(funding_coin.coin_id(), singleton_amount);
    let launcher_id = launcher.coin().coin_id();

    let (launcher_conditions, singleton_coin) = launcher
        .spend(ctx, inner_hash, ())
        .map_err(|e| anyhow::anyhow!("Launcher spend failed: {:?}", e))?;

    Ok((launcher_id, singleton_coin, launcher_conditions))
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
    let (action_hash, child_inner_hash, child_inner_tree_hash) = if use_action_1 {
        (config.action1_hash(), config.child_inner_1, child_inner_puzzle_hash())
    } else {
        (config.action2_hash(), config.child_inner_2, child_inner_puzzle_2_hash())
    };

    // Child launcher coin (ephemeral, 0-amount)
    let child_launcher_coin = Coin::new(
        singleton_coin.coin_id(),
        Bytes32::new(SINGLETON_LAUNCHER_PUZZLE_HASH),
        0,
    );
    let child_launcher_id = child_launcher_coin.coin_id();

    // Child singleton puzzle hash
    let child_singleton_hash: Bytes32 = SingletonArgs::curry_tree_hash(
        child_launcher_id,
        child_inner_tree_hash,
    ).into();

    // Create action layer
    let action_layer = config.create_action_layer(state);

    // Build action layer inner puzzle
    let inner_puzzle_ptr = action_layer.construct_puzzle(ctx)
        .map_err(|e| anyhow::anyhow!("Failed to construct action layer puzzle: {:?}", e))?;

    // Build curried action puzzle
    let action_puzzle = build_curried_action_puzzle(ctx, child_inner_hash)?;

    // Build action solution
    let action_solution = EmitChildActionSolution {
        my_singleton_coin_id: singleton_coin.coin_id(),
        child_singleton_puzzle_hash: child_singleton_hash,
    };
    let action_solution_ptr = ctx.alloc(&action_solution)
        .map_err(|e| anyhow::anyhow!("Failed to alloc action solution: {:?}", e))?;

    // CRITICAL: Use MerkleTree::proof directly (not ActionLayer::get_proofs)
    let merkle_tree = MerkleTree::new(&config.action_hashes());
    let merkle_proof = merkle_tree.proof(action_hash)
        .ok_or_else(|| anyhow::anyhow!("Failed to get merkle proof"))?;

    // Build action layer solution
    let action_layer_solution = ActionLayerSolution {
        proofs: vec![merkle_proof],
        action_spends: vec![Spend::new(action_puzzle, action_solution_ptr)],
        finalizer_solution: NodePtr::NIL,
    };

    let inner_solution = action_layer.construct_solution(ctx, action_layer_solution)
        .map_err(|e| anyhow::anyhow!("Failed to construct action layer solution: {:?}", e))?;

    // Build singleton puzzle and solution
    let singleton_puzzle = build_singleton_puzzle(ctx, launcher_id, inner_puzzle_ptr)?;
    let singleton_solution = build_singleton_solution(ctx, proof, singleton_coin.amount, inner_solution)?;

    // Create and insert singleton spend
    let singleton_spend = CoinSpend::new(
        singleton_coin.clone(),
        ctx.serialize(&singleton_puzzle).map_err(|e| anyhow::anyhow!("{:?}", e))?,
        ctx.serialize(&singleton_solution).map_err(|e| anyhow::anyhow!("{:?}", e))?,
    );
    ctx.insert(singleton_spend);

    // Spend child launcher (ephemeral, in same bundle)
    let (_child_conds, child_singleton_info) = Launcher::from_coin(child_launcher_coin, Conditions::new())
        .with_singleton_amount(1)
        .mint_vault(ctx, child_inner_tree_hash, ())
        .map_err(|e| anyhow::anyhow!("Child launcher mint_vault failed: {:?}", e))?;

    // Compute new state and parent coin
    let new_state = state.increment();
    let new_inner_hash = config.compute_inner_hash(new_state);
    let new_singleton_puzzle_hash: Bytes32 = SingletonArgs::curry_tree_hash(launcher_id, new_inner_hash).into();
    let new_parent_coin = Coin::new(
        singleton_coin.coin_id(),
        new_singleton_puzzle_hash,
        singleton_coin.amount,
    );

    Ok(EmitChildResult {
        child_launcher_id,
        child_singleton: child_singleton_info.coin,
        new_parent_coin,
        new_state,
    })
}

/// Create an eve proof for the first singleton spend
pub fn create_eve_proof(funding_coin_id: Bytes32, singleton_amount: u64) -> Proof {
    Proof::Eve(EveProof {
        parent_parent_coin_info: funding_coin_id,
        parent_amount: singleton_amount,
    })
}

/// Create a lineage proof for subsequent singleton spends
pub fn create_lineage_proof(
    parent_coin: &Coin,
    parent_inner_hash: TreeHash,
) -> Proof {
    Proof::Lineage(LineageProof {
        parent_parent_coin_info: parent_coin.parent_coin_info,
        parent_inner_puzzle_hash: parent_inner_hash.into(),
        parent_amount: parent_coin.amount,
    })
}

// ============================================================================
// Internal Helpers
// ============================================================================

fn build_curried_action_puzzle(
    ctx: &mut SpendContext,
    child_inner_hash: Bytes32,
) -> anyhow::Result<NodePtr> {
    let bytes = get_emit_child_action_bytes();
    let mod_hash = emit_child_action_mod_hash();
    let mod_ptr = ctx.puzzle(mod_hash, &bytes)
        .map_err(|e| anyhow::anyhow!("Failed to load puzzle: {:?}", e))?;
    ctx.alloc(&CurriedProgram {
        program: mod_ptr,
        args: EmitChildActionCurriedArgs { child_inner_puzzle_hash: child_inner_hash },
    }).map_err(|e| anyhow::anyhow!("Failed to curry: {:?}", e))
}

fn build_singleton_puzzle(
    ctx: &mut SpendContext,
    launcher_id: Bytes32,
    inner_puzzle: NodePtr,
) -> anyhow::Result<NodePtr> {
    let singleton_mod_hash = TreeHash::new(chia_puzzles::SINGLETON_TOP_LAYER_V1_1_HASH);
    let singleton_ptr = ctx.puzzle(singleton_mod_hash, &chia_puzzles::SINGLETON_TOP_LAYER_V1_1)
        .map_err(|e| anyhow::anyhow!("Failed to load singleton: {:?}", e))?;

    ctx.alloc(&CurriedProgram {
        program: singleton_ptr,
        args: SingletonArgs {
            singleton_struct: SingletonStruct::new(launcher_id),
            inner_puzzle,
        },
    }).map_err(|e| anyhow::anyhow!("Failed to curry singleton: {:?}", e))
}

fn build_singleton_solution(
    ctx: &mut SpendContext,
    proof: Proof,
    amount: u64,
    inner_solution: NodePtr,
) -> anyhow::Result<NodePtr> {
    ctx.alloc(&SingletonSolution { lineage_proof: proof, amount, inner_solution })
        .map_err(|e| anyhow::anyhow!("Failed to build solution: {:?}", e))
}
