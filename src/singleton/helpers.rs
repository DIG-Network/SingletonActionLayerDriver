//! Singleton helper functions
//!
//! Standalone helper functions for common singleton operations.

use chia::protocol::{Bytes32, Coin};
use chia::puzzles::singleton::SingletonArgs;
use chia::puzzles::{EveProof, LineageProof, Proof};
use chia_wallet_sdk::driver::{Launcher, SpendContext};
use chia_wallet_sdk::types::Conditions;
use clvm_utils::TreeHash;
use clvmr::NodePtr;

use super::driver::SINGLETON_LAUNCHER_PUZZLE_HASH;
use crate::DriverError;

// ============================================================================
// Proof Creation (for backward compatibility)
// ============================================================================

/// Create an eve proof for the first singleton spend (after launch)
pub fn create_eve_proof(launcher_parent_coin_id: Bytes32, singleton_amount: u64) -> Proof {
    Proof::Eve(EveProof {
        parent_parent_coin_info: launcher_parent_coin_id,
        parent_amount: singleton_amount,
    })
}

/// Create a lineage proof for subsequent singleton spends
pub fn create_lineage_proof(parent_coin: &Coin, parent_inner_puzzle_hash: TreeHash) -> Proof {
    Proof::Lineage(LineageProof {
        parent_parent_coin_info: parent_coin.parent_coin_info,
        parent_inner_puzzle_hash: parent_inner_puzzle_hash.into(),
        parent_amount: parent_coin.amount,
    })
}

// ============================================================================
// Puzzle Hash Computation
// ============================================================================

/// Compute the full singleton puzzle hash given launcher_id and inner puzzle hash
pub fn singleton_puzzle_hash(launcher_id: Bytes32, inner_puzzle_hash: TreeHash) -> Bytes32 {
    SingletonArgs::curry_tree_hash(launcher_id, inner_puzzle_hash).into()
}

/// Compute the puzzle hash for a child singleton given its launcher ID and inner puzzle hash
pub fn child_singleton_puzzle_hash(
    child_launcher_id: Bytes32,
    child_inner_puzzle_hash: TreeHash,
) -> Bytes32 {
    SingletonArgs::curry_tree_hash(child_launcher_id, child_inner_puzzle_hash).into()
}

/// Compute the expected child launcher ID given the parent singleton coin ID
pub fn expected_child_launcher_id(parent_singleton_coin_id: Bytes32) -> Bytes32 {
    Coin::new(
        parent_singleton_coin_id,
        Bytes32::new(SINGLETON_LAUNCHER_PUZZLE_HASH),
        0,
    )
    .coin_id()
}

// ============================================================================
// Child Singleton Spawning
// ============================================================================

/// Result of spawning a child singleton via ephemeral launcher
#[derive(Debug, Clone)]
pub struct ChildLaunchResult {
    pub child_launcher_id: Bytes32,
    pub child_singleton: Coin,
}

/// Spawn a child singleton via ephemeral (0-amount) launcher.
///
/// The launcher coin is parented by the parent singleton coin.
/// This is used when an action emits a child singleton.
pub fn spawn_child_singleton(
    ctx: &mut SpendContext,
    parent_coin_id: Bytes32,
    child_inner_puzzle_hash: TreeHash,
) -> Result<ChildLaunchResult, DriverError> {
    // Child launcher coin (ephemeral, 0-amount)
    let child_launcher_coin = Coin::new(
        parent_coin_id,
        Bytes32::new(SINGLETON_LAUNCHER_PUZZLE_HASH),
        0,
    );
    let child_launcher_id = child_launcher_coin.coin_id();

    // Spend the launcher to create the child singleton
    let (_child_conds, child_singleton_info) =
        Launcher::from_coin(child_launcher_coin, Conditions::new())
            .with_singleton_amount(1)
            .mint_vault(ctx, child_inner_puzzle_hash, ())
            .map_err(|e| DriverError::Launcher(format!("child spawn: {:?}", e)))?;

    Ok(ChildLaunchResult {
        child_launcher_id,
        child_singleton: child_singleton_info.coin,
    })
}

// ============================================================================
// Low-Level Puzzle Building (for advanced use cases)
// ============================================================================

use chia::puzzles::singleton::{SingletonSolution, SingletonStruct};
use clvm_utils::CurriedProgram;

/// Build a singleton puzzle NodePtr
pub fn build_singleton_puzzle(
    ctx: &mut SpendContext,
    launcher_id: Bytes32,
    inner_puzzle: NodePtr,
) -> Result<NodePtr, DriverError> {
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

/// Build a singleton solution NodePtr
pub fn build_singleton_solution(
    ctx: &mut SpendContext,
    proof: Proof,
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

/// Create and insert a singleton coin spend
pub fn create_singleton_coin_spend(
    ctx: &mut SpendContext,
    singleton_coin: &Coin,
    singleton_puzzle: NodePtr,
    singleton_solution: NodePtr,
) -> Result<(), DriverError> {
    use chia::protocol::CoinSpend;

    let puzzle_reveal = ctx
        .serialize(&singleton_puzzle)
        .map_err(|e| DriverError::Serialize(format!("{:?}", e)))?;
    let solution = ctx
        .serialize(&singleton_solution)
        .map_err(|e| DriverError::Serialize(format!("{:?}", e)))?;

    let coin_spend = CoinSpend::new(*singleton_coin, puzzle_reveal, solution);
    ctx.insert(coin_spend);
    Ok(())
}

/// Launch a new singleton with the given inner puzzle hash
///
/// For most use cases, prefer using `SingletonDriver::launch()` instead.
pub fn launch_singleton(
    ctx: &mut SpendContext,
    funding_coin: &Coin,
    inner_puzzle_hash: Bytes32,
    singleton_amount: u64,
) -> Result<super::LaunchResult, DriverError> {
    let launcher = Launcher::new(funding_coin.coin_id(), singleton_amount);
    let launcher_id = launcher.coin().coin_id();

    let (launcher_conditions, singleton_coin) = launcher
        .spend(ctx, inner_puzzle_hash, ())
        .map_err(|e| DriverError::Launcher(format!("{:?}", e)))?;

    Ok(super::LaunchResult {
        launcher_id,
        coin: singleton_coin,
        conditions: launcher_conditions,
    })
}
