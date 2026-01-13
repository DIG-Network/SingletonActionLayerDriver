//! Singlelaunch - A singleton that spawns children using Action Layer (CHIP-0050).
//!
//! This app demonstrates spawning child singletons from a parent using the SDK's
//! built-in Action Layer functionality:
//! - Action Layer wraps the singleton's inner puzzle
//! - emit_child action creates 0-amount launcher coin and asserts announcement
//! - Default finalizer handles singleton recreation
//!
//! Usage:
//!   singlelaunch wallet create           # Create a new wallet
//!   singlelaunch launch                  # Launch singleton and emit child on mainnet
//!   singlelaunch spend <launcher_id>     # Spend singleton to spawn another child
//!   singlelaunch status <launcher_id>    # Check singleton status

use clap::{Parser, Subcommand};
use console::style;
use std::path::PathBuf;

// SDK types (chia 0.26 / chia-wallet-sdk 0.30 for datalayer-driver compatibility)
use chia::protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia::bls::DerivableKey;

// SDK driver types - including Action Layer
use chia_wallet_sdk::driver::{SpendContext, StandardLayer, Launcher, Spend};
use chia_wallet_sdk::driver::{ActionLayer, Finalizer, Layer};
use chia_wallet_sdk::types::{Conditions, MAINNET_CONSTANTS, TESTNET11_CONSTANTS};
use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};

// CLVM types
use clvmr::{Allocator, NodePtr};
use clvmr::serde::node_from_bytes;

// Puzzle types with proper CLVM serialization
use chia::puzzles::{Proof, EveProof};
use chia::puzzles::singleton::{SingletonArgs, SingletonSolution, SingletonStruct};

// CLVM traits
use clvm_traits::{ToClvm, FromClvm};
use clvm_utils::{CurriedProgram, ToTreeHash, TreeHash};

// DL types (same version as SDK)
use datalayer_driver::Signature as DLSignature;
use datalayer_driver::async_api as dl;

type StandardArgs = chia::puzzles::standard::StandardArgs;

// ============================================================================
// Action Layer Puzzles
// ============================================================================

/// The compiled emit_child_action.rue - action that emits a child singleton
/// Curried with: (child_inner_puzzle_hash)
/// Solution: (my_singleton_coin_id, child_singleton_puzzle_hash)
/// Returns: ((new_state, nil), conditions) where conditions create launcher + assert announcement
const EMIT_CHILD_ACTION_HEX: &str = include_str!("../../../puzzles/output/emit_child_action.clvm.hex");

/// The compiled test_action.rue - simplest possible action for testing
/// No curried args, takes just state as input
/// Returns: ((state+1, nil), []) - increments state, no conditions
const TEST_ACTION_HEX: &str = include_str!("../../../puzzles/output/test_action.clvm.hex");

/// The compiled child_inner_puzzle.rue
/// This is the inner puzzle used for child singletons (just melts).
const CHILD_PUZZLE_HEX: &str = include_str!("../../../puzzles/output/child_inner_puzzle.clvm.hex");

/// Singleton launcher puzzle hash (standard)
const SINGLETON_LAUNCHER_PUZZLE_HASH: [u8; 32] = hex_literal::hex!(
    "eff07522495060c066f66f32acc2a77e3a3e737aca8baea4d1a64ea4cdc13da9"
);

// ============================================================================
// CLVM Types for Action Layer
// ============================================================================

/// Emit child action solution: (my_singleton_coin_id . child_singleton_puzzle_hash)
/// This is a cons pair, not a list - matches the Rue puzzle's type Solution = (Bytes32, Bytes32)
#[derive(Debug, Clone, ToClvm, FromClvm)]
#[clvm(list)]
pub struct EmitChildActionSolution {
    pub my_singleton_coin_id: Bytes32,
    #[clvm(rest)]
    pub child_singleton_puzzle_hash: Bytes32,
}

// ============================================================================
// Puzzle Loading and Hashing Functions
// ============================================================================

fn get_emit_child_action_bytes() -> Vec<u8> {
    hex::decode(EMIT_CHILD_ACTION_HEX.trim()).expect("valid hex in emit_child_action.clvm.hex")
}

fn get_test_action_bytes() -> Vec<u8> {
    hex::decode(TEST_ACTION_HEX.trim()).expect("valid hex in test_action.clvm.hex")
}

fn test_action_puzzle_hash() -> TreeHash {
    let puzzle_bytes = get_test_action_bytes();
    let mut allocator = Allocator::new();
    let puzzle_ptr = node_from_bytes(&mut allocator, &puzzle_bytes).expect("valid puzzle");
    chia::clvm_utils::tree_hash(&allocator, puzzle_ptr)
}

fn get_child_puzzle_bytes() -> Vec<u8> {
    hex::decode(CHILD_PUZZLE_HEX.trim()).expect("valid hex in child_inner_puzzle.clvm.hex")
}

fn emit_child_action_mod_hash() -> TreeHash {
    let puzzle_bytes = get_emit_child_action_bytes();
    let mut allocator = Allocator::new();
    let puzzle_ptr = node_from_bytes(&mut allocator, &puzzle_bytes).expect("valid puzzle");
    chia::clvm_utils::tree_hash(&allocator, puzzle_ptr)
}

fn child_inner_puzzle_hash() -> TreeHash {
    let puzzle_bytes = get_child_puzzle_bytes();
    let mut allocator = Allocator::new();
    let puzzle_ptr = node_from_bytes(&mut allocator, &puzzle_bytes).expect("valid puzzle");
    chia::clvm_utils::tree_hash(&allocator, puzzle_ptr)
}

/// Compute the emit_child_action puzzle hash (uncurried mod hash)
fn emit_child_action_puzzle_hash() -> TreeHash {
    // No currying needed - the puzzle takes state and solution directly
    emit_child_action_mod_hash()
}

/// Build emit_child_action puzzle (uncurried)
fn build_emit_child_action_puzzle(ctx: &mut SpendContext) -> anyhow::Result<NodePtr> {
    let puzzle_bytes = get_emit_child_action_bytes();
    let mod_hash = emit_child_action_mod_hash();

    // Just load the uncurried puzzle - no currying needed
    ctx.puzzle(mod_hash, &puzzle_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to load emit_child_action: {:?}", e))
}

/// Create an ActionLayer for the singleton with emit_child action
/// Uses TestState for proper cons cell structure
/// Returns the action layer and the action puzzle hash for the merkle tree
fn create_emit_child_action_layer(hint: Bytes32, initial_state: TestState) -> (ActionLayer<TestState>, Bytes32) {
    let action_hash: Bytes32 = emit_child_action_puzzle_hash().into();
    let action_hashes = vec![action_hash];

    let finalizer = Finalizer::Default { hint };
    let action_layer = ActionLayer::from_action_puzzle_hashes(
        &action_hashes,
        initial_state,
        finalizer,
    );

    (action_layer, action_hash)
}

/// State for testing action layer - mirrors CatalogRegistryState structure
/// Must be a proper cons cell (two fields) to avoid "path into atom" errors
/// The action layer CLVM puzzle expects state to be destructurable
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct TestState {
    /// First field - counter value (like cat_maker_puzzle_hash in CatalogRegistryState)
    pub counter: u64,
    /// Second field - marker value (like registration_price in CatalogRegistryState)
    #[clvm(rest)]
    pub marker: u64,
}

/// Create an ActionLayer with the simple test_action puzzle
/// Returns the action layer and the action puzzle hash
fn create_test_action_layer(hint: Bytes32, initial_state: TestState) -> (ActionLayer<TestState>, Bytes32) {
    let action_hash: Bytes32 = test_action_puzzle_hash().into();
    let action_hashes = vec![action_hash];

    let finalizer = Finalizer::Default { hint };
    let action_layer = ActionLayer::from_action_puzzle_hashes(
        &action_hashes,
        initial_state,
        finalizer,
    );

    (action_layer, action_hash)
}

/// Compute the action layer inner puzzle hash using test_action
fn compute_test_action_layer_inner_hash(hint: Bytes32, state: TestState) -> TreeHash {
    use chia_wallet_sdk::types::puzzles::{ActionLayerArgs, DefaultFinalizer2ndCurryArgs};
    use chia_wallet_sdk::types::MerkleTree;
    use clvm_utils::ToTreeHash;

    let action_hash: Bytes32 = test_action_puzzle_hash().into();
    let action_hashes = vec![action_hash];

    // Build merkle tree to get root
    let merkle_tree = MerkleTree::new(&action_hashes);
    let merkle_root = merkle_tree.root();

    // Compute finalizer hash (BOTH curry levels - 1st and 2nd)
    // This matches what ActionLayer::construct_puzzle produces
    let finalizer_hash = DefaultFinalizer2ndCurryArgs::curry_tree_hash(hint);

    // State hash - use the tree hash of the state struct
    let state_hash = state.tree_hash();

    // Compute action layer puzzle hash with state
    ActionLayerArgs::<TreeHash, TreeHash>::curry_tree_hash(
        finalizer_hash,
        merkle_root,
        state_hash,
    )
}

/// Compute the action layer inner puzzle hash for emit_child action
/// Uses TestState (proper cons cell structure)
fn compute_emit_child_action_layer_inner_hash(hint: Bytes32, state: TestState) -> TreeHash {
    use chia_wallet_sdk::types::puzzles::{ActionLayerArgs, DefaultFinalizer2ndCurryArgs};
    use chia_wallet_sdk::types::MerkleTree;
    use clvm_utils::ToTreeHash;

    let action_hash: Bytes32 = emit_child_action_puzzle_hash().into();
    let action_hashes = vec![action_hash];

    // Build merkle tree to get root
    let merkle_tree = MerkleTree::new(&action_hashes);
    let merkle_root = merkle_tree.root();

    // Compute finalizer hash (BOTH curry levels - 1st and 2nd)
    // This matches what ActionLayer::construct_puzzle produces
    let finalizer_hash = DefaultFinalizer2ndCurryArgs::curry_tree_hash(hint);

    // State hash - use ToTreeHash trait for TestState
    let state_hash = state.tree_hash();

    // Compute action layer puzzle hash with state
    ActionLayerArgs::<TreeHash, TreeHash>::curry_tree_hash(
        finalizer_hash,
        merkle_root,
        state_hash,
    )
}

/// Build singleton puzzle using SDK types (SingletonArgs)
fn build_singleton_puzzle(
    ctx: &mut SpendContext,
    launcher_id: Bytes32,
    inner_puzzle: NodePtr,
) -> anyhow::Result<NodePtr> {
    let singleton_mod_hash = TreeHash::new(chia_puzzles::SINGLETON_TOP_LAYER_V1_1_HASH);
    let singleton_ptr = ctx.puzzle(singleton_mod_hash, &chia_puzzles::SINGLETON_TOP_LAYER_V1_1)
        .map_err(|e| anyhow::anyhow!("Failed to load singleton module: {:?}", e))?;

    let args = SingletonArgs {
        singleton_struct: SingletonStruct::new(launcher_id),
        inner_puzzle,
    };

    ctx.alloc(&CurriedProgram {
        program: singleton_ptr,
        args,
    }).map_err(|e| anyhow::anyhow!("Failed to curry singleton puzzle: {:?}", e))
}

/// Build singleton solution using SDK types (SingletonSolution)
fn build_singleton_solution(
    ctx: &mut SpendContext,
    proof: Proof,
    amount: u64,
    inner_solution: NodePtr,
) -> anyhow::Result<NodePtr> {
    let solution = SingletonSolution {
        lineage_proof: proof,
        amount,
        inner_solution,
    };

    ctx.alloc(&solution)
        .map_err(|e| anyhow::anyhow!("Failed to build singleton solution: {:?}", e))
}

#[derive(Parser)]
#[command(name = "singlelaunch")]
#[command(about = "Singleton spawner using Action Layer (CHIP-0050)")]
#[command(version)]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Wallet {
        #[command(subcommand)]
        cmd: WalletCommands,
    },

    /// Create and immediately spawn a child singleton (all-in-one)
    Launch {
        #[arg(long)]
        testnet: bool,
        #[arg(long, default_value = "default")]
        wallet: String,
        #[arg(long, default_value = "100000")]
        fee: u64,
        #[arg(long, env = "SINGLELAUNCH_PASSWORD")]
        password: Option<String>,
        /// Amount in mojos for the child singleton (must be odd, default: 3)
        #[arg(long, default_value = "3")]
        child_amount: u64,
    },

    /// Create a new spawner singleton (without spawning)
    Create {
        #[arg(long)]
        testnet: bool,
        #[arg(long, default_value = "default")]
        wallet: String,
        #[arg(long, default_value = "100000")]
        fee: u64,
        #[arg(long, env = "SINGLELAUNCH_PASSWORD")]
        password: Option<String>,
        /// Amount in mojos for child singletons when spawning (must be odd, default: 3)
        #[arg(long, default_value = "3")]
        child_amount: u64,
    },

    /// Spend existing singleton to recreate + optionally spawn child
    Spend {
        launcher_id: String,
        #[arg(long)]
        funding_parent: Option<String>,
        #[arg(long)]
        testnet: bool,
        #[arg(long, default_value = "default")]
        wallet: String,
        #[arg(long, default_value = "100000")]
        fee: u64,
        #[arg(long, env = "SINGLELAUNCH_PASSWORD")]
        password: Option<String>,
        /// Don't spawn a child singleton, just recreate the parent
        #[arg(long)]
        no_spawn: bool,
        /// Amount in mojos for the child singleton (default: 3, must be odd)
        #[arg(long, default_value = "3")]
        child_amount: u64,
    },

    /// Check singleton status
    Status {
        launcher_id: String,
        #[arg(long)]
        testnet: bool,
        #[arg(long, default_value = "default")]
        wallet: String,
        #[arg(long, env = "SINGLELAUNCH_PASSWORD")]
        password: Option<String>,
    },

    /// Test action layer with simplest possible action (no child spawn)
    Test {
        #[arg(long)]
        testnet: bool,
        #[arg(long, default_value = "default")]
        wallet: String,
        #[arg(long, default_value = "100000")]
        fee: u64,
        #[arg(long, env = "SINGLELAUNCH_PASSWORD")]
        password: Option<String>,
    },

    /// Offline test of action layer puzzle (no network)
    OfflineTest,

    /// Test emit child action - creates singleton and spawns child via action layer
    EmitChild {
        #[arg(long)]
        testnet: bool,
        #[arg(long, default_value = "default")]
        wallet: String,
        #[arg(long, default_value = "100000")]
        fee: u64,
        #[arg(long, env = "SINGLELAUNCH_PASSWORD")]
        password: Option<String>,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    Create {
        #[arg(default_value = "default")]
        name: String,
        #[arg(long)]
        show_mnemonic: bool,
        #[arg(short, long)]
        force: bool,
        #[arg(long, env = "SINGLELAUNCH_PASSWORD")]
        password: Option<String>,
    },
    Show {
        #[arg(default_value = "default")]
        name: String,
        #[arg(long, env = "SINGLELAUNCH_PASSWORD")]
        password: Option<String>,
    },
    Balance {
        #[arg(default_value = "default")]
        name: String,
        #[arg(long)]
        testnet: bool,
        #[arg(long, env = "SINGLELAUNCH_PASSWORD")]
        password: Option<String>,
    },
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Transaction error: {0}")]
    Transaction(String),
    #[error("Wallet not found: {0}")]
    WalletNotFound(String),
    #[error("Invalid passphrase")]
    InvalidPassphrase,
    #[error("Insufficient funds: {0}")]
    InsufficientFunds(String),
    #[error("Singleton not found: {0}")]
    SingletonNotFound(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    match cli.command {
        Commands::Wallet { cmd } => run_wallet_command(cmd).await?,
        Commands::Launch { testnet, wallet, fee, password, child_amount } => {
            launch_and_spawn(testnet, &wallet, fee, password, child_amount).await?;
        }
        Commands::Create { testnet, wallet, fee, password, child_amount } => {
            create_singleton(testnet, &wallet, fee, password, child_amount).await?;
        }
        Commands::Spend { launcher_id, funding_parent, testnet, wallet, fee, password, no_spawn, child_amount } => {
            spend_singleton(&launcher_id, funding_parent.as_deref(), testnet, &wallet, fee, password, !no_spawn, child_amount).await?;
        }
        Commands::Status { launcher_id, testnet, wallet, password } => {
            check_status(&launcher_id, testnet, &wallet, password).await?;
        }
        Commands::Test { testnet, wallet, fee, password } => {
            test_action_layer(testnet, &wallet, fee, password).await?;
        }
        Commands::OfflineTest => {
            run_offline_test()?;
        }
        Commands::EmitChild { testnet, wallet, fee, password } => {
            test_emit_child_action(testnet, &wallet, fee, password).await?;
        }
    }

    Ok(())
}

// ============================================================================
// Wallet Commands
// ============================================================================

async fn run_wallet_command(cmd: WalletCommands) -> Result<()> {
    match cmd {
        WalletCommands::Create { name, show_mnemonic, force, password } => {
            create_wallet(&name, show_mnemonic, force, password).await
        }
        WalletCommands::Show { name, password } => {
            show_wallet(&name, password).await
        }
        WalletCommands::Balance { name, testnet, password } => {
            check_balance(&name, testnet, password).await
        }
    }
}

async fn create_wallet(name: &str, show_mnemonic: bool, force: bool, password: Option<String>) -> Result<()> {
    use dialoguer::Password;

    println!("Creating new wallet...");

    let wallet_dir = get_wallet_dir()?;
    let wallet_path = wallet_dir.join(format!("{}.wallet", name));

    if wallet_path.exists() && !force {
        return Err(Error::Config(format!(
            "Wallet '{}' already exists. Use --force to overwrite.", name
        )));
    }

    let passphrase = match password {
        Some(p) => p,
        None => Password::new()
            .with_prompt("Enter encryption passphrase")
            .with_confirmation("Confirm passphrase", "Passphrases don't match")
            .interact()
            .map_err(|e| Error::Config(e.to_string()))?,
    };

    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let secret_key = chia::bls::SecretKey::from_seed(&seed);

    let mnemonic = generate_mnemonic()?;

    std::fs::create_dir_all(&wallet_dir)?;
    save_encrypted_wallet(&wallet_path, &secret_key, &passphrase)?;

    let derived_sk = secret_key
        .derive_hardened(12381)
        .derive_hardened(8444)
        .derive_hardened(2)
        .derive_unhardened(0);
    let derived_pk = derived_sk.public_key();
    let address = compute_address(&derived_pk);

    println!("{} Wallet created!", style("✓").green().bold());
    println!("  Name: {}", name);
    println!("  Address: {}", address);

    if show_mnemonic {
        println!();
        println!("{}", style("IMPORTANT: Back up your mnemonic!").yellow().bold());
        println!("  {}", mnemonic);
    }

    Ok(())
}

async fn show_wallet(name: &str, password: Option<String>) -> Result<()> {
    use dialoguer::Password;

    let wallet_path = get_wallet_dir()?.join(format!("{}.wallet", name));
    if !wallet_path.exists() {
        return Err(Error::WalletNotFound(name.to_string()));
    }

    let passphrase = match password {
        Some(p) => p,
        None => Password::new()
            .with_prompt("Enter passphrase")
            .interact()
            .map_err(|e| Error::Config(e.to_string()))?,
    };

    let master_sk = load_encrypted_wallet(&wallet_path, &passphrase)?;

    let derived_sk = master_sk
        .derive_hardened(12381)
        .derive_hardened(8444)
        .derive_hardened(2)
        .derive_unhardened(0);
    let derived_pk = derived_sk.public_key();
    let address = compute_address(&derived_pk);
    let puzzle_hash = compute_puzzle_hash(&derived_pk);

    println!("Wallet: {}", name);
    println!("  Address: {}", address);
    println!("  Puzzle Hash: 0x{}", hex::encode(puzzle_hash));

    Ok(())
}

async fn check_balance(name: &str, testnet: bool, password: Option<String>) -> Result<()> {
    use dialoguer::Password;

    let wallet_path = get_wallet_dir()?.join(format!("{}.wallet", name));
    if !wallet_path.exists() {
        return Err(Error::WalletNotFound(name.to_string()));
    }

    let passphrase = match password {
        Some(p) => p,
        None => Password::new()
            .with_prompt("Enter passphrase")
            .interact()
            .map_err(|e| Error::Config(e.to_string()))?,
    };

    let master_sk = load_encrypted_wallet(&wallet_path, &passphrase)?;

    let derived_sk = master_sk
        .derive_hardened(12381)
        .derive_hardened(8444)
        .derive_hardened(2)
        .derive_unhardened(0);
    let derived_pk = derived_sk.public_key();
    let address = compute_address(&derived_pk);

    println!("Connecting to {}...", if testnet { "testnet" } else { "mainnet" });

    let peer = connect_peer(testnet).await?;
    let genesis = get_genesis_challenge(testnet);

    let puzzle_hash = StandardArgs::curry_tree_hash(derived_pk);
    let puzzle_hash_dl = Bytes32::new(puzzle_hash.to_bytes());

    let coins = dl::get_all_unspent_coins(&peer, puzzle_hash_dl, None, genesis)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    let total: u64 = coins.coin_states.iter().map(|c| c.coin.amount).sum();

    println!();
    println!("Wallet: {}", name);
    println!("  Address: {}", address);
    println!("  Balance: {} mojos ({:.6} XCH)", total, total as f64 / 1e12);
    println!("  Coins: {}", coins.coin_states.len());

    Ok(())
}

// ============================================================================
// Singleton Commands (using Rigidity's emitter pattern)
// ============================================================================

async fn create_singleton(testnet: bool, wallet_name: &str, fee: u64, password: Option<String>, _child_amount: u64) -> Result<()> {
    use dialoguer::Password;

    let singleton_amount: u64 = 1;

    println!("Creating emitter singleton on {}...", if testnet { "testnet" } else { "mainnet" });
    println!("  Pattern: Rigidity's singleton emitter (no action layer)");
    println!("  Singleton amount: {} mojo", singleton_amount);

    // Load wallet
    let wallet_path = get_wallet_dir()?.join(format!("{}.wallet", wallet_name));
    if !wallet_path.exists() {
        return Err(Error::WalletNotFound(wallet_name.to_string()));
    }

    let passphrase = match password {
        Some(p) => p,
        None => Password::new()
            .with_prompt("Enter wallet passphrase")
            .interact()
            .map_err(|e| Error::Config(e.to_string()))?,
    };

    let master_sk = load_encrypted_wallet(&wallet_path, &passphrase)?;

    let derived_sk = master_sk
        .derive_hardened(12381)
        .derive_hardened(8444)
        .derive_hardened(2)
        .derive_unhardened(0);
    let derived_pk = derived_sk.public_key();

    let standard_layer = StandardLayer::new(derived_pk.clone());
    let wallet_puzzle_hash: Bytes32 = standard_layer.tree_hash().into();

    // Compute the action layer inner puzzle hash
    // hint = wallet puzzle hash (for tracking/hints)
    // state = TestState (proper cons cell structure)
    let initial_state = TestState { counter: 1, marker: 0xDEADBEEF };
    let inner_puzzle_hash = compute_emit_child_action_layer_inner_hash(wallet_puzzle_hash, initial_state);
    println!("  Action layer inner puzzle hash: 0x{}", hex::encode(inner_puzzle_hash.to_bytes()));
    println!("  Pattern: Action Layer (CHIP-0050)");

    // Connect to network
    let peer = connect_peer(testnet).await?;
    let genesis = get_genesis_challenge(testnet);

    // Get wallet coins
    let puzzle_hash_tree = StandardArgs::curry_tree_hash(derived_pk.clone());
    let puzzle_hash_dl = Bytes32::new(puzzle_hash_tree.to_bytes());

    let coins = dl::get_all_unspent_coins(&peer, puzzle_hash_dl, None, genesis)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if coins.coin_states.is_empty() {
        return Err(Error::InsufficientFunds("No coins in wallet".to_string()));
    }

    let required = singleton_amount + fee;
    let funding_coin_old = coins.coin_states.iter()
        .find(|cs| cs.coin.amount >= required)
        .map(|cs| &cs.coin)
        .ok_or_else(|| Error::InsufficientFunds(format!("Need {} mojos", required)))?;

    let funding_coin = Coin::new(
        Bytes32::new(funding_coin_old.parent_coin_info.to_bytes()),
        Bytes32::new(funding_coin_old.puzzle_hash.to_bytes()),
        funding_coin_old.amount,
    );

    println!("  Funding coin: 0x{}... ({} mojos)",
        hex::encode(&funding_coin.coin_id().to_bytes()[..8]),
        funding_coin.amount);

    let ctx = &mut SpendContext::new();

    let launcher = Launcher::new(funding_coin.coin_id(), singleton_amount);
    let launcher_id = launcher.coin().coin_id();

    println!("  Launcher ID: 0x{}", hex::encode(launcher_id.to_bytes()));

    let inner_puzzle_hash_bytes32: Bytes32 = inner_puzzle_hash.into();

    let (launcher_conditions, singleton_coin) = launcher
        .spend(ctx, inner_puzzle_hash_bytes32, ())
        .map_err(|e| Error::Transaction(format!("Launcher spend failed: {:?}", e)))?;

    println!("  Singleton puzzle hash: 0x{}", hex::encode(singleton_coin.puzzle_hash.to_bytes()));

    // Build funding coin spend
    let change = funding_coin.amount - singleton_amount - fee;
    let mut conditions = launcher_conditions;

    if change > 0 {
        conditions = conditions.create_coin(wallet_puzzle_hash, change, chia::puzzles::Memos::None);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }

    standard_layer.spend(ctx, funding_coin.clone(), conditions)
        .map_err(|e| Error::Transaction(format!("Funding coin spend failed: {:?}", e)))?;

    // Sign and broadcast
    let coin_spends = ctx.take();
    println!("  Signing {} coin spend(s)...", coin_spends.len());

    let signature = sign_coin_spends(&coin_spends, &derived_sk, testnet)
        .map_err(|e| Error::Transaction(format!("Signing failed: {:?}", e)))?;

    let dl_spends = convert_spends_to_dl(&coin_spends);
    let dl_sig = DLSignature::from_bytes(&signature.to_bytes())
        .map_err(|_| Error::Transaction("Invalid signature bytes".to_string()))?;

    let bundle = SpendBundle::new(dl_spends, dl_sig);

    println!("  Broadcasting transaction...");
    let result = dl::broadcast_spend_bundle(&peer, bundle)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if result.status == 3 {
        let err = result.error.unwrap_or_default();
        return Err(Error::Transaction(format!("Broadcast failed: {}", err)));
    }

    println!("  Transaction submitted to mempool");
    println!();

    // Wait for confirmation
    let singleton_puzzle_hash_dl = Bytes32::new(singleton_coin.puzzle_hash.to_bytes());
    wait_for_coin_confirmation(
        &peer,
        singleton_puzzle_hash_dl,
        singleton_coin.coin_id(),
        genesis,
        "Singleton",
    ).await?;

    println!();
    println!("{} Emitter singleton created and confirmed!", style("✓").green().bold());
    println!();
    println!("  Launcher ID: 0x{}", hex::encode(launcher_id.to_bytes()));
    println!("  Singleton Coin ID: 0x{}", hex::encode(singleton_coin.coin_id().to_bytes()));
    println!("  Inner Puzzle: Emitter (Rigidity pattern)");
    println!();
    println!("To spend and emit a child:");
    println!("  singlelaunch spend 0x{} --funding-parent 0x{}{}",
        hex::encode(launcher_id.to_bytes()),
        hex::encode(funding_coin.coin_id().to_bytes()),
        if testnet { " --testnet" } else { "" });

    Ok(())
}

/// All-in-one: Create singleton, wait for confirmation, then spend to emit child
async fn launch_and_spawn(testnet: bool, wallet_name: &str, fee: u64, password: Option<String>, _child_amount: u64) -> Result<()> {
    use dialoguer::Password;

    let singleton_amount: u64 = 1;

    println!("{}", style("=== LAUNCH & EMIT (Rigidity Pattern) ===").cyan().bold());
    println!("Network: {}", if testnet { "testnet" } else { "mainnet" });
    println!("Pattern: Rigidity singleton emitter");
    println!("Singleton amount: {} mojo", singleton_amount);
    println!("Child singleton amount: 1 mojo");
    println!();

    // Load wallet
    let wallet_path = get_wallet_dir()?.join(format!("{}.wallet", wallet_name));
    if !wallet_path.exists() {
        return Err(Error::WalletNotFound(wallet_name.to_string()));
    }

    let passphrase = match password {
        Some(p) => p,
        None => Password::new()
            .with_prompt("Enter wallet passphrase")
            .interact()
            .map_err(|e| Error::Config(e.to_string()))?,
    };

    let master_sk = load_encrypted_wallet(&wallet_path, &passphrase)?;

    let derived_sk = master_sk
        .derive_hardened(12381)
        .derive_hardened(8444)
        .derive_hardened(2)
        .derive_unhardened(0);
    let derived_pk = derived_sk.public_key();

    let standard_layer = StandardLayer::new(derived_pk.clone());
    let wallet_puzzle_hash: Bytes32 = standard_layer.tree_hash().into();

    // Compute action layer inner puzzle hash - using TestState (proper cons cell)
    let initial_state = TestState { counter: 1, marker: 0xDEADBEEF };
    let action_layer_inner_hash = compute_emit_child_action_layer_inner_hash(wallet_puzzle_hash, initial_state);
    println!("  Action layer inner puzzle hash: 0x{}", hex::encode(action_layer_inner_hash.to_bytes()));

    // Connect to network
    let peer = connect_peer(testnet).await?;
    let genesis = get_genesis_challenge(testnet);

    // Get wallet coins
    let puzzle_hash_tree = StandardArgs::curry_tree_hash(derived_pk.clone());
    let puzzle_hash_dl = Bytes32::new(puzzle_hash_tree.to_bytes());

    let coins = dl::get_all_unspent_coins(&peer, puzzle_hash_dl, None, genesis)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if coins.coin_states.is_empty() {
        return Err(Error::InsufficientFunds("No coins in wallet".to_string()));
    }

    let required = singleton_amount + fee * 2;
    let funding_coin_old = coins.coin_states.iter()
        .find(|cs| cs.coin.amount >= required)
        .map(|cs| &cs.coin)
        .ok_or_else(|| Error::InsufficientFunds(format!("Need {} mojos", required)))?;

    let funding_coin = Coin::new(
        Bytes32::new(funding_coin_old.parent_coin_info.to_bytes()),
        Bytes32::new(funding_coin_old.puzzle_hash.to_bytes()),
        funding_coin_old.amount,
    );

    // =========================================================================
    // STEP 1: Create the singleton with action layer inner puzzle
    // =========================================================================
    println!("{}", style("--- Step 1: Creating Action Layer Singleton ---").yellow().bold());

    let ctx = &mut SpendContext::new();

    let launcher = Launcher::new(funding_coin.coin_id(), singleton_amount);
    let launcher_id = launcher.coin().coin_id();

    println!("  Launcher ID: 0x{}", hex::encode(launcher_id.to_bytes()));

    let inner_hash_bytes32: Bytes32 = action_layer_inner_hash.into();

    let (launcher_conditions, singleton_coin) = launcher
        .spend(ctx, inner_hash_bytes32, ())
        .map_err(|e| Error::Transaction(format!("Launcher spend failed: {:?}", e)))?;

    // Build funding coin spend (for creation)
    let change_after_create = funding_coin.amount - singleton_amount - fee;
    let mut conditions = launcher_conditions;

    if change_after_create > 0 {
        conditions = conditions.create_coin(wallet_puzzle_hash, change_after_create, chia::puzzles::Memos::None);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }

    standard_layer.spend(ctx, funding_coin.clone(), conditions)
        .map_err(|e| Error::Transaction(format!("Funding coin spend failed: {:?}", e)))?;

    // Sign and broadcast creation
    let coin_spends = ctx.take();
    println!("  Signing {} coin spend(s)...", coin_spends.len());

    let signature = sign_coin_spends(&coin_spends, &derived_sk, testnet)
        .map_err(|e| Error::Transaction(format!("Signing failed: {:?}", e)))?;

    let dl_spends = convert_spends_to_dl(&coin_spends);
    let dl_sig = DLSignature::from_bytes(&signature.to_bytes())
        .map_err(|_| Error::Transaction("Invalid signature bytes".to_string()))?;

    let bundle = SpendBundle::new(dl_spends, dl_sig);

    println!("  Broadcasting creation transaction...");
    let result = dl::broadcast_spend_bundle(&peer, bundle)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if result.status == 3 {
        let err = result.error.unwrap_or_default();
        return Err(Error::Transaction(format!("Broadcast failed: {}", err)));
    }

    // Wait for singleton confirmation
    let singleton_puzzle_hash_dl = Bytes32::new(singleton_coin.puzzle_hash.to_bytes());
    wait_for_coin_confirmation(
        &peer,
        singleton_puzzle_hash_dl,
        singleton_coin.coin_id(),
        genesis,
        "Singleton",
    ).await?;

    println!("  {} Singleton created!", style("✓").green().bold());

    // =========================================================================
    // STEP 2: Spend singleton using Action Layer to emit child
    // =========================================================================
    println!();
    println!("{}", style("--- Step 2: Emitting Child via Action Layer ---").yellow().bold());

    let ctx = &mut SpendContext::new();

    // The child launcher will be created by the emit_child action with amount 0
    let child_launcher_coin = Coin::new(
        singleton_coin.coin_id(),
        Bytes32::new(SINGLETON_LAUNCHER_PUZZLE_HASH),
        0,
    );
    let child_launcher_id = child_launcher_coin.coin_id();

    println!("  Child launcher ID: 0x{}", hex::encode(child_launcher_id.to_bytes()));

    // Compute the child singleton puzzle hash using SDK (this must match what launcher creates)
    let child_hash = child_inner_puzzle_hash();
    let sdk_child_singleton_hash: Bytes32 = SingletonArgs::curry_tree_hash(child_launcher_id, child_hash).into();
    println!("  Child singleton puzzle hash (SDK): 0x{}", hex::encode(sdk_child_singleton_hash.to_bytes()));

    // Create the ActionLayer for spending
    let (action_layer, action_puzzle_hash) = create_emit_child_action_layer(wallet_puzzle_hash, initial_state);
    println!("  DEBUG: Created ActionLayer with action hash: 0x{}", hex::encode(action_puzzle_hash.to_bytes()));

    // Build the action layer inner puzzle using Layer trait
    let inner_puzzle_ptr = action_layer.construct_puzzle(ctx)
        .map_err(|e| Error::Transaction(format!("Failed to construct action layer puzzle: {:?}", e)))?;

    // Debug: compute the action layer puzzle hash using serialize
    let inner_puzzle_bytes = ctx.serialize(&inner_puzzle_ptr)
        .map_err(|e| Error::Transaction(format!("{:?}", e)))?;
    println!("  DEBUG: Action layer inner puzzle size: {} bytes", Vec::<u8>::from(inner_puzzle_bytes).len());

    // Build the emit_child action puzzle and solution
    let emit_action_puzzle = build_emit_child_action_puzzle(ctx)
        .map_err(|e| Error::Transaction(format!("Failed to build emit_child action: {:?}", e)))?;

    let emit_action_solution = EmitChildActionSolution {
        my_singleton_coin_id: singleton_coin.coin_id(),
        child_singleton_puzzle_hash: sdk_child_singleton_hash,
    };
    let emit_action_solution_ptr = ctx.alloc(&emit_action_solution)
        .map_err(|e| Error::Transaction(format!("Failed to alloc action solution: {:?}", e)))?;

    // Get merkle proof for the action
    let action_hashes = vec![action_puzzle_hash];
    println!("  DEBUG: Action puzzle hash: 0x{}", hex::encode(action_puzzle_hash.to_bytes()));

    let proofs = action_layer.get_proofs(&action_hashes, &[action_puzzle_hash])
        .ok_or_else(|| Error::Transaction("Failed to get merkle proofs".to_string()))?;

    println!("  DEBUG: Got {} merkle proofs", proofs.len());
    for (i, proof) in proofs.iter().enumerate() {
        println!("    Proof {}: path={}, proof_len={}", i, proof.path, proof.proof.len());
    }

    // Build the action layer solution
    use chia_wallet_sdk::driver::ActionLayerSolution;

    // Use NodePtr::NIL for finalizer_solution (for Default finalizer)
    let finalizer_sol = clvmr::NodePtr::NIL;

    let action_layer_solution = ActionLayerSolution {
        proofs,
        action_spends: vec![Spend::new(emit_action_puzzle, emit_action_solution_ptr)],
        finalizer_solution: finalizer_sol,
    };

    println!("  DEBUG: Building action layer solution...");
    let inner_solution = action_layer.construct_solution(ctx, action_layer_solution)
        .map_err(|e| Error::Transaction(format!("Failed to construct action layer solution: {:?}", e)))?;

    // Debug: print inner solution structure
    let inner_sol_bytes = ctx.serialize(&inner_solution).map_err(|e| Error::Transaction(format!("{:?}", e)))?;
    let inner_sol_vec: Vec<u8> = inner_sol_bytes.into();
    println!("  DEBUG: Action layer inner solution size: {} bytes", inner_sol_vec.len());
    println!("  DEBUG: Inner solution hex (first 100): {}", hex::encode(&inner_sol_vec[..std::cmp::min(100, inner_sol_vec.len())]));

    // Also print the action solution we built
    let action_sol_bytes = ctx.serialize(&emit_action_solution_ptr).map_err(|e| Error::Transaction(format!("{:?}", e)))?;
    let action_sol_vec: Vec<u8> = action_sol_bytes.into();
    println!("  DEBUG: Action solution (my_coin_id, child_hash) hex: {}", hex::encode(&action_sol_vec));

    println!("  DEBUG: Action layer solution built successfully");

    // Build singleton solution
    let eve_proof = Proof::Eve(EveProof {
        parent_parent_coin_info: funding_coin.coin_id(),
        parent_amount: singleton_amount,
    });

    let singleton_solution = build_singleton_solution(ctx, eve_proof, singleton_coin.amount, inner_solution)
        .map_err(|e| Error::Transaction(format!("Failed to build singleton solution: {:?}", e)))?;

    // Build singleton puzzle
    let singleton_puzzle = build_singleton_puzzle(ctx, launcher_id, inner_puzzle_ptr)
        .map_err(|e| Error::Transaction(format!("Failed to build singleton puzzle: {:?}", e)))?;

    // Debug: print solution structure
    let solution_bytes = ctx.serialize(&singleton_solution).map_err(|e| Error::Transaction(format!("{:?}", e)))?;
    let solution_vec: Vec<u8> = solution_bytes.clone().into();
    println!("  DEBUG: Singleton solution size: {} bytes", solution_vec.len());
    println!("  DEBUG: Singleton solution hex (first 200): {}", hex::encode(&solution_vec[..std::cmp::min(200, solution_vec.len())]));

    let singleton_spend = CoinSpend::new(
        singleton_coin.clone(),
        ctx.serialize(&singleton_puzzle).map_err(|e| Error::Transaction(format!("{:?}", e)))?,
        solution_bytes,
    );

    ctx.insert(singleton_spend);

    // Spend child launcher to create child singleton
    let (_child_launcher_conds, child_singleton) = Launcher::from_coin(child_launcher_coin.clone(), Conditions::new())
        .with_singleton_amount(1)
        .mint_vault(ctx, child_hash, ())
        .map_err(|e| Error::Transaction(format!("Child launcher mint_vault failed: {:?}", e)))?;

    println!("  Child singleton ID: 0x{}", hex::encode(child_singleton.coin.coin_id().to_bytes()));

    // Fund child singleton (needs 1 mojo)
    let child_funding_needed: u64 = 1;
    let total_needed = child_funding_needed + fee;

    if change_after_create >= total_needed {
        let fee_coin = Coin::new(
            funding_coin.coin_id(),
            wallet_puzzle_hash,
            change_after_create,
        );

        let change_after_spend = change_after_create - total_needed;
        let mut fee_conditions = Conditions::new();
        if fee > 0 {
            fee_conditions = fee_conditions.reserve_fee(fee);
        }
        if change_after_spend > 0 {
            fee_conditions = fee_conditions.create_coin(wallet_puzzle_hash, change_after_spend, chia::puzzles::Memos::None);
        }

        standard_layer.spend(ctx, fee_coin, fee_conditions)
            .map_err(|e| Error::Transaction(format!("Fee coin spend failed: {:?}", e)))?;
    } else {
        return Err(Error::InsufficientFunds(format!(
            "Need {} mojos for child funding + fee, have {}",
            total_needed, change_after_create
        )));
    }

    // Sign and broadcast spawn
    let coin_spends = ctx.take();
    println!("  Signing {} coin spend(s)...", coin_spends.len());

    // Debug: Test the emit_child action puzzle directly (uncurried)
    println!("  DEBUG: Testing emit_child_action puzzle directly...");
    {
        let mut test_alloc = Allocator::new();
        let action_bytes = get_emit_child_action_bytes();
        let action_puzzle = node_from_bytes(&mut test_alloc, &action_bytes).unwrap();

        // Build state as TestState structure: (ephemeral . (counter . marker))
        // ephemeral = nil, counter = 1, marker = 0xDEADBEEF
        let nil = test_alloc.nil();
        let marker = test_alloc.new_number(0xDEADBEEFu64.into()).unwrap();
        let counter = test_alloc.new_number(1.into()).unwrap();
        let persistent = test_alloc.new_pair(counter, marker).unwrap();
        let state = test_alloc.new_pair(nil, persistent).unwrap();

        // Build solution: (my_coin_id . child_hash)
        let coin_id_atom = test_alloc.new_atom(&singleton_coin.coin_id().to_bytes()).unwrap();
        let child_hash_atom = test_alloc.new_atom(&sdk_child_singleton_hash.to_bytes()).unwrap();
        let solution = test_alloc.new_pair(coin_id_atom, child_hash_atom).unwrap();

        // Build env: (state . solution)
        let env = test_alloc.new_pair(state, solution).unwrap();

        match clvmr::run_program(
            &mut test_alloc,
            &clvmr::ChiaDialect::new(0),
            action_puzzle,
            env,
            11_000_000_000,
        ) {
            Ok(reduction) => {
                println!("    Action puzzle ran successfully! cost={}", reduction.0);
            }
            Err(e) => {
                println!("    Action puzzle FAILED: {:?}", e);
            }
        }
    }

    // Debug: Test with SIMPLEST action first (test_action - no currying, no solution args)
    println!("  DEBUG: Testing action layer with simple test_action...");
    {
        use clvmr::SExp;

        let mut test_alloc = Allocator::new();

        // Load uncurried test_action puzzle
        let test_action_bytes = get_test_action_bytes();
        let test_action_mod = node_from_bytes(&mut test_alloc, &test_action_bytes).unwrap();
        let test_action_hash = chia::clvm_utils::tree_hash(&test_alloc, test_action_mod);
        println!("    test_action mod hash: 0x{}", hex::encode(test_action_hash.to_bytes()));

        // Test running test_action directly with state=0
        // test_action takes just state as input, returns ((state+1, nil), [])
        let state_0 = test_alloc.new_number(0.into()).unwrap();
        let nil = test_alloc.nil();
        let test_sol = test_alloc.new_pair(state_0, nil).unwrap(); // (0) - list with just state

        match clvmr::run_program(
            &mut test_alloc,
            &clvmr::ChiaDialect::new(0),
            test_action_mod,
            test_sol,
            11_000_000_000,
        ) {
            Ok(reduction) => {
                println!("    test_action direct run OK! cost={}", reduction.0);
                // Print the result
                let result_bytes = clvmr::serde::node_to_bytes(&test_alloc, reduction.1).unwrap();
                println!("    result: {}", hex::encode(&result_bytes));
            }
            Err(e) => {
                println!("    test_action direct run FAILED: {:?}", e);
            }
        }

        // Now test through action layer
        // Create action layer with test_action
        let test_action_hash_bytes: Bytes32 = test_action_hash.into();
        let test_finalizer: Finalizer<()> = Finalizer::Default { hint: wallet_puzzle_hash };
        let test_action_layer = ActionLayer::from_action_puzzle_hashes(
            &[test_action_hash_bytes],
            0i64, // initial state
            test_finalizer,
        );

        // Build action layer puzzle
        let test_ctx = &mut SpendContext::new();
        let test_al_puzzle = test_action_layer.construct_puzzle(test_ctx).unwrap();

        // Build action layer solution with test_action
        // test_action has NO curried args and NO solution args (just state from action layer)
        let test_action_puzzle_ptr = test_ctx.puzzle(test_action_hash, &test_action_bytes).unwrap();

        // For test_action, the solution is empty (just nil) since it only takes state
        let empty_solution = test_ctx.alloc(&()).unwrap();

        let test_proofs = test_action_layer.get_proofs(&[test_action_hash_bytes], &[test_action_hash_bytes]).unwrap();
        println!("    test_action proofs: {} proofs", test_proofs.len());
        for (i, p) in test_proofs.iter().enumerate() {
            println!("      proof {}: path={}, proof_len={}", i, p.path, p.proof.len());
        }

        use chia_wallet_sdk::driver::ActionLayerSolution;
        let test_al_solution = ActionLayerSolution {
            proofs: test_proofs,
            action_spends: vec![Spend::new(test_action_puzzle_ptr, empty_solution)],
            finalizer_solution: clvmr::NodePtr::NIL,
        };

        let test_inner_sol = test_action_layer.construct_solution(test_ctx, test_al_solution).unwrap();

        // Serialize and print
        let al_puzzle_bytes = test_ctx.serialize(&test_al_puzzle).unwrap();
        let al_sol_bytes = test_ctx.serialize(&test_inner_sol).unwrap();
        let al_puzzle_vec: Vec<u8> = al_puzzle_bytes.into();
        let al_sol_vec: Vec<u8> = al_sol_bytes.into();

        println!("    Action layer puzzle: {} bytes", al_puzzle_vec.len());
        println!("    Action layer solution: {} bytes", al_sol_vec.len());
        println!("    Solution hex: {}", hex::encode(&al_sol_vec));

        // Deserialize in test allocator and run
        let al_puzzle_ptr = node_from_bytes(&mut test_alloc, &al_puzzle_vec).unwrap();
        let al_sol_ptr = node_from_bytes(&mut test_alloc, &al_sol_vec).unwrap();

        // Parse solution structure
        println!("    Parsing solution structure...");
        match test_alloc.sexp(al_sol_ptr) {
            SExp::Pair(puzzles, rest1) => {
                let puz_bytes = clvmr::serde::node_to_bytes(&test_alloc, puzzles).unwrap();
                println!("      puzzles: {} bytes", puz_bytes.len());
                match test_alloc.sexp(rest1) {
                    SExp::Pair(sel_proofs, rest2) => {
                        let sp_bytes = clvmr::serde::node_to_bytes(&test_alloc, sel_proofs).unwrap();
                        println!("      selectors_and_proofs: {} bytes = {}", sp_bytes.len(), hex::encode(&sp_bytes));
                        match test_alloc.sexp(rest2) {
                            SExp::Pair(solutions, rest3) => {
                                let sol_bytes = clvmr::serde::node_to_bytes(&test_alloc, solutions).unwrap();
                                println!("      solutions: {} bytes = {}", sol_bytes.len(), hex::encode(&sol_bytes));
                                match test_alloc.sexp(rest3) {
                                    SExp::Pair(fin_sol, _) => {
                                        let fin_bytes = clvmr::serde::node_to_bytes(&test_alloc, fin_sol).unwrap();
                                        println!("      finalizer_solution: {} bytes = {}", fin_bytes.len(), hex::encode(&fin_bytes));
                                    }
                                    SExp::Atom => println!("      rest3 is atom (nil = no finalizer sol)"),
                                }
                            }
                            SExp::Atom => println!("      rest2 is atom"),
                        }
                    }
                    SExp::Atom => println!("      rest1 is atom"),
                }
            }
            SExp::Atom => println!("      solution is atom"),
        }

        match clvmr::run_program(
            &mut test_alloc,
            &clvmr::ChiaDialect::new(0),
            al_puzzle_ptr,
            al_sol_ptr,
            11_000_000_000,
        ) {
            Ok(reduction) => {
                println!("    Action layer with test_action OK! cost={}", reduction.0);
            }
            Err(e) => {
                println!("    Action layer with test_action FAILED: {:?}", e);
            }
        }
    }

    // Debug: Test ActionLayer with emit_child_action in isolation
    println!("  DEBUG: Testing ActionLayer with emit_child_action in isolation...");
    {
        let mut test_alloc = Allocator::new();

        // Create action layer with emit_child
        let emit_hash: Bytes32 = emit_child_action_puzzle_hash().into();
        let emit_finalizer: Finalizer<()> = Finalizer::Default { hint: wallet_puzzle_hash };
        let emit_action_layer: ActionLayer<i64> = ActionLayer::from_action_puzzle_hashes(
            &[emit_hash],
            1i64, // state = 1 (not 0 to avoid nil issues)
            emit_finalizer,
        );

        // Build action layer puzzle
        let test_ctx = &mut SpendContext::new();
        let emit_al_puzzle = emit_action_layer.construct_puzzle(test_ctx).unwrap();

        // Build the curried emit_child puzzle
        let emit_puzzle_ptr = build_emit_child_action_puzzle(test_ctx).unwrap();

        // Create a fake solution for testing
        // Use known bytes32 values to avoid any potential issues
        let fake_coin_id = Bytes32::from([0x11u8; 32]);
        let fake_child_hash = Bytes32::from([0x22u8; 32]);
        let emit_sol = EmitChildActionSolution {
            my_singleton_coin_id: fake_coin_id,
            child_singleton_puzzle_hash: fake_child_hash,
        };
        let emit_sol_ptr = test_ctx.alloc(&emit_sol).unwrap();

        // Get proofs
        let emit_proofs = emit_action_layer.get_proofs(&[emit_hash], &[emit_hash]).unwrap();
        println!("    emit_child proofs: {} proofs", emit_proofs.len());
        for (i, p) in emit_proofs.iter().enumerate() {
            println!("      proof {}: path={}, proof_len={}", i, p.path, p.proof.len());
        }

        // Build action layer solution
        let emit_al_solution = ActionLayerSolution {
            proofs: emit_proofs,
            action_spends: vec![Spend::new(emit_puzzle_ptr, emit_sol_ptr)],
            finalizer_solution: clvmr::NodePtr::NIL,
        };

        let emit_inner_sol = emit_action_layer.construct_solution(test_ctx, emit_al_solution).unwrap();

        // Serialize
        let al_puzzle_bytes = test_ctx.serialize(&emit_al_puzzle).unwrap();
        let al_sol_bytes = test_ctx.serialize(&emit_inner_sol).unwrap();
        let al_puzzle_vec: Vec<u8> = al_puzzle_bytes.into();
        let al_sol_vec: Vec<u8> = al_sol_bytes.into();

        println!("    Action layer puzzle: {} bytes", al_puzzle_vec.len());
        println!("    Action layer solution: {} bytes", al_sol_vec.len());
        println!("    Solution hex (first 100): {}", hex::encode(&al_sol_vec[..std::cmp::min(100, al_sol_vec.len())]));

        // Deserialize in test allocator and run
        let al_puzzle_ptr = node_from_bytes(&mut test_alloc, &al_puzzle_vec).unwrap();
        let al_sol_ptr = node_from_bytes(&mut test_alloc, &al_sol_vec).unwrap();

        match clvmr::run_program(
            &mut test_alloc,
            &clvmr::ChiaDialect::new(0),
            al_puzzle_ptr,
            al_sol_ptr,
            11_000_000_000,
        ) {
            Ok(reduction) => {
                println!("    ActionLayer with emit_child OK! cost={}", reduction.0);
                let result_hex = clvmr::serde::node_to_bytes(&test_alloc, reduction.1).unwrap();
                println!("    Result (first 100): {}", hex::encode(&result_hex[..std::cmp::min(100, result_hex.len())]));
            }
            Err(e) => {
                println!("    ActionLayer with emit_child FAILED: {:?}", e);
            }
        }
    }

    // Debug: Test the action layer puzzle directly
    println!("  DEBUG: Testing action layer puzzle directly...");
    {
        let mut test_alloc = Allocator::new();

        // Deserialize the action layer inner puzzle from the singleton spend
        let _puzzle_bytes: Vec<u8> = coin_spends[0].puzzle_reveal.clone().into();
        let solution_bytes: Vec<u8> = coin_spends[0].solution.clone().into();

        // The singleton puzzle wraps the inner puzzle, so we need to extract just the inner parts
        // For now, let's parse the inner solution from the singleton solution
        let singleton_sol = node_from_bytes(&mut test_alloc, &solution_bytes).unwrap();

        // Singleton solution is (lineage_proof amount inner_solution)
        // Get inner_solution (third element = first of rest of rest)
        // Use allocator.sexp() which returns SExp enum
        use clvmr::SExp;

        let rest1 = match test_alloc.sexp(singleton_sol) {
            SExp::Pair(_, rest) => rest,
            _ => panic!("singleton_sol should be a pair"),
        };
        let rest2 = match test_alloc.sexp(rest1) {
            SExp::Pair(_, rest) => rest,
            _ => panic!("rest1 should be a pair"),
        };
        let inner_solution = match test_alloc.sexp(rest2) {
            SExp::Pair(first, _) => first,
            _ => panic!("rest2 should be a pair"),
        };

        // Serialize inner solution to check it
        let inner_sol_hex = clvmr::serde::node_to_bytes(&test_alloc, inner_solution).unwrap();
        println!("    Extracted inner solution: {} bytes, starts with: {}",
            inner_sol_hex.len(),
            hex::encode(&inner_sol_hex[..std::cmp::min(50, inner_sol_hex.len())]));

        // Parse the structure of inner_solution
        // Expected: ((proofs . action_spends) . finalizer_solution)
        // where each action_spend is (puzzle . solution) and each proof is (path . proof_hashes)
        println!("    Parsing inner solution structure...");
        match test_alloc.sexp(inner_solution) {
            SExp::Pair(first_pair, finalizer_sol) => {
                let fin_bytes = clvmr::serde::node_to_bytes(&test_alloc, finalizer_sol).unwrap();
                println!("      finalizer_solution: {} bytes = {}", fin_bytes.len(), hex::encode(&fin_bytes));

                match test_alloc.sexp(first_pair) {
                    SExp::Pair(proofs, action_spends) => {
                        // Parse proofs
                        let proofs_bytes = clvmr::serde::node_to_bytes(&test_alloc, proofs).unwrap();
                        println!("      proofs: {} bytes = {}", proofs_bytes.len(), hex::encode(&proofs_bytes));

                        // Parse action_spends
                        let action_bytes = clvmr::serde::node_to_bytes(&test_alloc, action_spends).unwrap();
                        println!("      action_spends: {} bytes", action_bytes.len());

                        // Parse first action_spend
                        match test_alloc.sexp(action_spends) {
                            SExp::Pair(first_action, _rest) => {
                                match test_alloc.sexp(first_action) {
                                    SExp::Pair(action_puzzle, action_sol) => {
                                        let puz_bytes = clvmr::serde::node_to_bytes(&test_alloc, action_puzzle).unwrap();
                                        let sol_bytes = clvmr::serde::node_to_bytes(&test_alloc, action_sol).unwrap();
                                        println!("        first action puzzle: {} bytes", puz_bytes.len());
                                        println!("        first action solution: {} bytes = {}", sol_bytes.len(), hex::encode(&sol_bytes));
                                    }
                                    SExp::Atom => println!("        first action is an atom (unexpected)"),
                                }
                            }
                            SExp::Atom => println!("      action_spends is an atom (nil = no actions)"),
                        }
                    }
                    SExp::Atom => println!("      first_pair is an atom (unexpected)"),
                }
            }
            SExp::Atom => println!("      inner_solution is an atom (unexpected)"),
        }

        // Now test the action layer puzzle directly
        // Build the action layer puzzle
        let (test_action_layer, _) = create_emit_child_action_layer(wallet_puzzle_hash, initial_state);
        let test_ctx = &mut SpendContext::new();
        let action_layer_puzzle = test_action_layer.construct_puzzle(test_ctx).unwrap();

        // Serialize action layer puzzle
        let al_puzzle_bytes = test_ctx.serialize(&action_layer_puzzle).unwrap();
        let al_puzzle_vec: Vec<u8> = al_puzzle_bytes.into();
        println!("    Action layer puzzle: {} bytes", al_puzzle_vec.len());

        // Deserialize in test allocator and run
        let al_puzzle_ptr = node_from_bytes(&mut test_alloc, &al_puzzle_vec).unwrap();

        match clvmr::run_program(
            &mut test_alloc,
            &clvmr::ChiaDialect::new(0),
            al_puzzle_ptr,
            inner_solution,
            11_000_000_000,
        ) {
            Ok(reduction) => {
                println!("    Action layer puzzle ran successfully! cost={}", reduction.0);
            }
            Err(e) => {
                println!("    Action layer puzzle FAILED: {:?}", e);
            }
        }
    }

    // Debug: Print each coin spend and try running them
    for (i, spend) in coin_spends.iter().enumerate() {
        println!("  --- Coin Spend {} ---", i);
        println!("    Coin: 0x{}...", hex::encode(&spend.coin.coin_id().to_bytes()[..8]));
        let puzzle_bytes: Vec<u8> = spend.puzzle_reveal.clone().into();
        let solution_bytes: Vec<u8> = spend.solution.clone().into();
        println!("    Puzzle reveal len: {} bytes", puzzle_bytes.len());
        println!("    Solution len: {} bytes", solution_bytes.len());

        // Try to run this spend
        let mut test_allocator = Allocator::new();
        let puzzle_ptr = match node_from_bytes(&mut test_allocator, &puzzle_bytes) {
            Ok(p) => p,
            Err(e) => {
                println!("    ERROR: Failed to parse puzzle: {:?}", e);
                continue;
            }
        };
        let solution_ptr = match node_from_bytes(&mut test_allocator, &solution_bytes) {
            Ok(s) => s,
            Err(e) => {
                println!("    ERROR: Failed to parse solution: {:?}", e);
                continue;
            }
        };

        // Run puzzle with solution
        match clvmr::run_program(
            &mut test_allocator,
            &clvmr::ChiaDialect::new(0),
            puzzle_ptr,
            solution_ptr,
            11_000_000_000,
        ) {
            Ok(reduction) => {
                println!("    OK: Puzzle ran successfully, cost={}", reduction.0);
            }
            Err(e) => {
                println!("    ERROR: Puzzle execution failed: {:?}", e);
            }
        }
    }

    let signature = sign_coin_spends(&coin_spends, &derived_sk, testnet)
        .map_err(|e| Error::Transaction(format!("Signing failed: {:?}", e)))?;

    let dl_spends = convert_spends_to_dl(&coin_spends);
    let dl_sig = DLSignature::from_bytes(&signature.to_bytes())
        .map_err(|_| Error::Transaction("Invalid signature bytes".to_string()))?;

    let bundle = SpendBundle::new(dl_spends, dl_sig);

    println!("  Broadcasting emit transaction...");
    let result = dl::broadcast_spend_bundle(&peer, bundle)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if result.status == 3 {
        let err = result.error.unwrap_or_default();
        return Err(Error::Transaction(format!("Broadcast failed: {}", err)));
    }

    // Wait for child singleton confirmation
    let child_singleton_puzzle_hash_dl = Bytes32::new(child_singleton.coin.puzzle_hash.to_bytes());
    wait_for_coin_confirmation(
        &peer,
        child_singleton_puzzle_hash_dl,
        child_singleton.coin.coin_id(),
        genesis,
        "Child singleton",
    ).await?;

    // =========================================================================
    // Done!
    // =========================================================================
    println!();
    println!("{}", style("=== LAUNCH COMPLETE ===").green().bold());
    println!();
    println!("  Parent Launcher ID: 0x{}", hex::encode(launcher_id.to_bytes()));
    println!("  Child Launcher ID:  0x{}", hex::encode(child_launcher_id.to_bytes()));
    println!("  Child Singleton ID: 0x{}", hex::encode(child_singleton.coin.coin_id().to_bytes()));
    println!("  Child Amount:       1 mojo");
    println!();
    println!("Pattern: Rigidity singleton emitter");

    Ok(())
}

/// Spend an existing action layer singleton to emit a child singleton.
async fn spend_singleton(
    launcher_id_hex: &str,
    funding_parent_hex: Option<&str>,
    testnet: bool,
    wallet_name: &str,
    fee: u64,
    password: Option<String>,
    _spawn_child: bool,
    _child_amount: u64,
) -> Result<()> {
    use dialoguer::Password;
    use chia_wallet_sdk::driver::ActionLayerSolution;

    println!("Spending action layer singleton on {}...", if testnet { "testnet" } else { "mainnet" });
    println!("  Pattern: Action Layer (CHIP-0050)");

    // Parse launcher ID
    let launcher_id_hex = launcher_id_hex.strip_prefix("0x").unwrap_or(launcher_id_hex);
    let launcher_id_bytes: [u8; 32] = hex::decode(launcher_id_hex)
        .map_err(|e| Error::Config(format!("Invalid launcher ID: {}", e)))?
        .try_into()
        .map_err(|_| Error::Config("Launcher ID must be 32 bytes".to_string()))?;
    let launcher_id = Bytes32::new(launcher_id_bytes);

    // Load wallet
    let wallet_path = get_wallet_dir()?.join(format!("{}.wallet", wallet_name));
    if !wallet_path.exists() {
        return Err(Error::WalletNotFound(wallet_name.to_string()));
    }

    let passphrase = match password {
        Some(p) => p,
        None => Password::new()
            .with_prompt("Enter wallet passphrase")
            .interact()
            .map_err(|e| Error::Config(e.to_string()))?,
    };

    let master_sk = load_encrypted_wallet(&wallet_path, &passphrase)?;

    let derived_sk = master_sk
        .derive_hardened(12381)
        .derive_hardened(8444)
        .derive_hardened(2)
        .derive_unhardened(0);
    let derived_pk = derived_sk.public_key();

    let standard_layer = StandardLayer::new(derived_pk.clone());
    let wallet_puzzle_hash: Bytes32 = standard_layer.tree_hash().into();

    // Connect to network
    let peer = connect_peer(testnet).await?;
    let genesis = get_genesis_challenge(testnet);

    // State tracking - using TestState (proper cons cell)
    // In a real implementation, you'd track state on-chain or via a database
    let current_state = TestState { counter: 1, marker: 0xDEADBEEF };

    // Compute action layer inner puzzle hash with wallet_puzzle_hash as hint
    let action_layer_inner_hash = compute_emit_child_action_layer_inner_hash(wallet_puzzle_hash, current_state);

    // Find the singleton coin
    let singleton_puzzle_hash: Bytes32 = SingletonArgs::curry_tree_hash(
        launcher_id,
        action_layer_inner_hash,
    ).into();

    println!("  Singleton puzzle hash: 0x{}", hex::encode(singleton_puzzle_hash.to_bytes()));

    let singleton_ph_dl = Bytes32::new(singleton_puzzle_hash.to_bytes());
    let singleton_coins = dl::get_all_unspent_coins(&peer, singleton_ph_dl, None, genesis)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if singleton_coins.coin_states.is_empty() {
        return Err(Error::SingletonNotFound(format!("0x{}", hex::encode(launcher_id.to_bytes()))));
    }

    let singleton_coin_dl = &singleton_coins.coin_states[0].coin;
    let singleton_coin = Coin::new(
        Bytes32::new(singleton_coin_dl.parent_coin_info.to_bytes()),
        Bytes32::new(singleton_coin_dl.puzzle_hash.to_bytes()),
        singleton_coin_dl.amount,
    );

    println!("  Found singleton coin: 0x{}...", hex::encode(&singleton_coin.coin_id().to_bytes()[..8]));

    // Check if eve spend
    let is_eve = singleton_coin.parent_coin_info == launcher_id;
    println!("  Is eve spend: {}", is_eve);

    if is_eve && funding_parent_hex.is_none() {
        return Err(Error::Config(
            "Eve spend requires --funding-parent".to_string()
        ));
    }

    // Get fee coin from wallet
    let puzzle_hash_tree = StandardArgs::curry_tree_hash(derived_pk.clone());
    let puzzle_hash_dl = Bytes32::new(puzzle_hash_tree.to_bytes());

    let wallet_coins = dl::get_all_unspent_coins(&peer, puzzle_hash_dl, None, genesis)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    let fee_coin_old = wallet_coins.coin_states.iter()
        .find(|cs| cs.coin.amount >= fee)
        .map(|cs| &cs.coin);

    let ctx = &mut SpendContext::new();

    // Build lineage proof
    let proof = if is_eve {
        let funding_parent = funding_parent_hex.unwrap();
        let funding_parent = funding_parent.strip_prefix("0x").unwrap_or(funding_parent);
        let funding_parent_bytes: [u8; 32] = hex::decode(funding_parent)
            .map_err(|e| Error::Config(format!("Invalid funding parent: {}", e)))?
            .try_into()
            .map_err(|_| Error::Config("Funding parent must be 32 bytes".to_string()))?;

        println!("  Launcher parent (funding coin): 0x{}...", hex::encode(&funding_parent_bytes[..8]));

        Proof::Eve(EveProof {
            parent_parent_coin_info: Bytes32::new(funding_parent_bytes),
            parent_amount: singleton_coin.amount,
        })
    } else {
        return Err(Error::Transaction(
            "Non-eve spends require lineage tracking (not implemented yet)".to_string()
        ));
    };

    // The child launcher is created by the emit_child action with amount 0
    let child_launcher_coin = Coin::new(
        singleton_coin.coin_id(),
        Bytes32::new(SINGLETON_LAUNCHER_PUZZLE_HASH),
        0,
    );
    let child_launcher_id = child_launcher_coin.coin_id();

    println!("  Child launcher ID: 0x{}", hex::encode(child_launcher_id.to_bytes()));

    // Compute the child singleton puzzle hash using SDK (this must match what launcher creates)
    let child_hash = child_inner_puzzle_hash();
    let sdk_child_singleton_hash: Bytes32 = SingletonArgs::curry_tree_hash(child_launcher_id, child_hash).into();
    println!("  Child singleton puzzle hash (SDK): 0x{}", hex::encode(sdk_child_singleton_hash.to_bytes()));

    // Create the ActionLayer for spending
    let (action_layer, action_puzzle_hash) = create_emit_child_action_layer(wallet_puzzle_hash, current_state);

    // Build the action layer inner puzzle using Layer trait
    let inner_puzzle_ptr = action_layer.construct_puzzle(ctx)
        .map_err(|e| Error::Transaction(format!("Failed to construct action layer puzzle: {:?}", e)))?;

    // Build the emit_child action puzzle and solution
    let emit_action_puzzle = build_emit_child_action_puzzle(ctx)
        .map_err(|e| Error::Transaction(format!("Failed to build emit_child action: {:?}", e)))?;

    let emit_action_solution = EmitChildActionSolution {
        my_singleton_coin_id: singleton_coin.coin_id(),
        child_singleton_puzzle_hash: sdk_child_singleton_hash,
    };
    let emit_action_solution_ptr = ctx.alloc(&emit_action_solution)
        .map_err(|e| Error::Transaction(format!("Failed to alloc action solution: {:?}", e)))?;

    // Get merkle proof for the action
    let action_hashes = vec![action_puzzle_hash];
    let proofs = action_layer.get_proofs(&action_hashes, &[action_puzzle_hash])
        .ok_or_else(|| Error::Transaction("Failed to get merkle proofs".to_string()))?;

    // Build the action layer solution
    let action_layer_solution = ActionLayerSolution {
        proofs,
        action_spends: vec![Spend::new(emit_action_puzzle, emit_action_solution_ptr)],
        finalizer_solution: ctx.alloc(&()).map_err(|e| Error::Transaction(format!("{:?}", e)))?,
    };

    let inner_solution = action_layer.construct_solution(ctx, action_layer_solution)
        .map_err(|e| Error::Transaction(format!("Failed to construct action layer solution: {:?}", e)))?;

    // Build singleton solution
    let singleton_solution = build_singleton_solution(ctx, proof, singleton_coin.amount, inner_solution)
        .map_err(|e| Error::Transaction(format!("Failed to build singleton solution: {:?}", e)))?;

    let singleton_puzzle = build_singleton_puzzle(ctx, launcher_id, inner_puzzle_ptr)
        .map_err(|e| Error::Transaction(format!("Failed to build singleton puzzle: {:?}", e)))?;

    let singleton_spend = CoinSpend::new(
        singleton_coin.clone(),
        ctx.serialize(&singleton_puzzle).map_err(|e| Error::Transaction(format!("{:?}", e)))?,
        ctx.serialize(&singleton_solution).map_err(|e| Error::Transaction(format!("{:?}", e)))?,
    );

    ctx.insert(singleton_spend);

    // Spend child launcher to create child singleton
    let (_child_launcher_conds, child_singleton) = Launcher::from_coin(child_launcher_coin.clone(), Conditions::new())
        .with_singleton_amount(1)
        .mint_vault(ctx, child_hash, ())
        .map_err(|e| Error::Transaction(format!("Child launcher mint_vault failed: {:?}", e)))?;

    println!("  Child singleton will be: 0x{}...", hex::encode(&child_singleton.coin.coin_id().to_bytes()[..8]));

    // Fund child singleton (needs 1 mojo + fee)
    let child_funding_needed: u64 = 1;
    let total_needed = child_funding_needed + fee;

    if let Some(fee_coin_old) = fee_coin_old {
        let fee_coin = Coin::new(
            Bytes32::new(fee_coin_old.parent_coin_info.to_bytes()),
            Bytes32::new(fee_coin_old.puzzle_hash.to_bytes()),
            fee_coin_old.amount,
        );

        if fee_coin.amount < total_needed {
            return Err(Error::InsufficientFunds(format!(
                "Need {} mojos for child funding + fee, have {}",
                total_needed, fee_coin.amount
            )));
        }

        let change = fee_coin.amount - total_needed;
        let mut fee_conditions = Conditions::new();
        if fee > 0 {
            fee_conditions = fee_conditions.reserve_fee(fee);
        }
        if change > 0 {
            fee_conditions = fee_conditions.create_coin(wallet_puzzle_hash, change, chia::puzzles::Memos::None);
        }

        standard_layer.spend(ctx, fee_coin, fee_conditions)
            .map_err(|e| Error::Transaction(format!("Fee coin spend failed: {:?}", e)))?;
    } else {
        return Err(Error::InsufficientFunds(format!(
            "Need {} mojos for child funding + fee",
            total_needed
        )));
    }

    // Sign and broadcast
    let coin_spends = ctx.take();
    println!("  Signing {} coin spend(s)...", coin_spends.len());

    let signature = sign_coin_spends(&coin_spends, &derived_sk, testnet)
        .map_err(|e| Error::Transaction(format!("Signing failed: {:?}", e)))?;

    let dl_spends = convert_spends_to_dl(&coin_spends);
    let dl_sig = DLSignature::from_bytes(&signature.to_bytes())
        .map_err(|_| Error::Transaction("Invalid signature bytes".to_string()))?;

    let bundle = SpendBundle::new(dl_spends, dl_sig);

    println!("  Broadcasting transaction...");
    let result = dl::broadcast_spend_bundle(&peer, bundle)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if result.status == 3 {
        let err = result.error.unwrap_or_default();
        return Err(Error::Transaction(format!("Broadcast failed: {}", err)));
    }

    println!("  Transaction submitted to mempool");
    println!();

    // Wait for child singleton confirmation
    let child_singleton_puzzle_hash = Bytes32::new(child_singleton.coin.puzzle_hash.to_bytes());
    wait_for_coin_confirmation(
        &peer,
        child_singleton_puzzle_hash,
        child_singleton.coin.coin_id(),
        genesis,
        "Child singleton",
    ).await?;

    println!();
    println!("{} Singleton spent! Child emitted!", style("✓").green().bold());
    println!();
    println!("  Parent launcher ID: 0x{}", hex::encode(launcher_id.to_bytes()));
    println!("  Child launcher ID:  0x{}", hex::encode(child_launcher_id.to_bytes()));
    println!("  Child singleton ID: 0x{}", hex::encode(child_singleton.coin.coin_id().to_bytes()));
    println!();
    println!("Pattern: Action Layer (CHIP-0050)");

    Ok(())
}

async fn check_status(launcher_id_hex: &str, testnet: bool, wallet_name: &str, password: Option<String>) -> Result<()> {
    use dialoguer::Password;

    let launcher_id_hex = launcher_id_hex.strip_prefix("0x").unwrap_or(launcher_id_hex);
    let launcher_id_bytes: [u8; 32] = hex::decode(launcher_id_hex)
        .map_err(|e| Error::Config(format!("Invalid launcher ID: {}", e)))?
        .try_into()
        .map_err(|_| Error::Config("Launcher ID must be 32 bytes".to_string()))?;
    let launcher_id = Bytes32::new(launcher_id_bytes);

    println!("Checking singleton status on {}...", if testnet { "testnet" } else { "mainnet" });
    println!("  Pattern: Action Layer (CHIP-0050)");

    // Load wallet to get the hint (wallet_puzzle_hash)
    let wallet_path = get_wallet_dir()?.join(format!("{}.wallet", wallet_name));
    if !wallet_path.exists() {
        return Err(Error::WalletNotFound(wallet_name.to_string()));
    }

    let passphrase = match password {
        Some(p) => p,
        None => Password::new()
            .with_prompt("Enter wallet passphrase")
            .interact()
            .map_err(|e| Error::Config(e.to_string()))?,
    };

    let master_sk = load_encrypted_wallet(&wallet_path, &passphrase)?;

    let derived_sk = master_sk
        .derive_hardened(12381)
        .derive_hardened(8444)
        .derive_hardened(2)
        .derive_unhardened(0);
    let derived_pk = derived_sk.public_key();

    let standard_layer = StandardLayer::new(derived_pk);
    let wallet_puzzle_hash: Bytes32 = standard_layer.tree_hash().into();

    let peer = connect_peer(testnet).await?;
    let genesis = get_genesis_challenge(testnet);

    // State tracking - using TestState (proper cons cell)
    // In a real implementation, you'd track state or iterate through possible states
    let current_state = TestState { counter: 1, marker: 0xDEADBEEF };

    // Compute the action layer inner puzzle hash
    let inner_puzzle_hash = compute_emit_child_action_layer_inner_hash(wallet_puzzle_hash, current_state);
    let singleton_puzzle_hash: Bytes32 = SingletonArgs::curry_tree_hash(
        launcher_id,
        inner_puzzle_hash,
    ).into();

    let singleton_ph_dl = Bytes32::new(singleton_puzzle_hash.to_bytes());
    let coins = dl::get_all_unspent_coins(&peer, singleton_ph_dl, None, genesis)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    println!();
    println!("  Launcher ID: 0x{}", launcher_id_hex);
    println!("  Singleton puzzle hash: 0x{}", hex::encode(singleton_puzzle_hash.to_bytes()));
    println!("  Inner puzzle: Action Layer (state={:?})", current_state);
    println!();

    if coins.coin_states.is_empty() {
        println!("  Status: {}", style("NOT FOUND").red());
        println!("  The singleton may have been melted, never created, or is at a different state.");
    } else {
        println!("  Status: {}", style("ACTIVE").green().bold());
        println!("  Coin ID: 0x{}", hex::encode(coins.coin_states[0].coin.coin_id().to_bytes()));
        println!("  Amount: {} mojo", coins.coin_states[0].coin.amount);
    }

    Ok(())
}

/// Test action layer with simplest possible action (just increments state)
/// This isolates action layer issues from child spawning complexity
async fn test_action_layer(testnet: bool, wallet_name: &str, fee: u64, password: Option<String>) -> Result<()> {
    use dialoguer::Password;
    use chia_wallet_sdk::driver::ActionLayerSolution;

    let singleton_amount: u64 = 1;

    println!("{}", style("=== TEST ACTION LAYER (Simple Action) ===").cyan().bold());
    println!("Network: {}", if testnet { "testnet" } else { "mainnet" });
    println!("Pattern: Action Layer with test_action (increment state only)");
    println!("This test uses the simplest possible action to isolate issues.");
    println!();

    // Load wallet
    let wallet_path = get_wallet_dir()?.join(format!("{}.wallet", wallet_name));
    if !wallet_path.exists() {
        return Err(Error::WalletNotFound(wallet_name.to_string()));
    }

    let passphrase = match password {
        Some(p) => p,
        None => Password::new()
            .with_prompt("Enter wallet passphrase")
            .interact()
            .map_err(|e| Error::Config(e.to_string()))?,
    };

    let master_sk = load_encrypted_wallet(&wallet_path, &passphrase)?;

    let derived_sk = master_sk
        .derive_hardened(12381)
        .derive_hardened(8444)
        .derive_hardened(2)
        .derive_unhardened(0);
    let derived_pk = derived_sk.public_key();

    let standard_layer = StandardLayer::new(derived_pk.clone());
    let wallet_puzzle_hash: Bytes32 = standard_layer.tree_hash().into();

    // Compute action layer inner puzzle hash using test_action
    // Use non-zero values to ensure state is a proper cons cell structure
    let initial_state = TestState { counter: 1, marker: 0xDEADBEEF };
    let action_layer_inner_hash = compute_test_action_layer_inner_hash(wallet_puzzle_hash, initial_state);
    println!("  Test action puzzle hash: 0x{}", hex::encode(test_action_puzzle_hash().to_bytes()));
    println!("  Action layer inner hash (state=TestState): 0x{}", hex::encode(action_layer_inner_hash.to_bytes()));

    // Connect to network
    let peer = connect_peer(testnet).await?;
    let genesis = get_genesis_challenge(testnet);

    // Get wallet coins
    let puzzle_hash_tree = StandardArgs::curry_tree_hash(derived_pk.clone());
    let puzzle_hash_dl = Bytes32::new(puzzle_hash_tree.to_bytes());

    let coins = dl::get_all_unspent_coins(&peer, puzzle_hash_dl, None, genesis)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if coins.coin_states.is_empty() {
        return Err(Error::InsufficientFunds("No coins in wallet".to_string()));
    }

    let required = singleton_amount + fee * 2;
    let funding_coin_old = coins.coin_states.iter()
        .find(|cs| cs.coin.amount >= required)
        .map(|cs| &cs.coin)
        .ok_or_else(|| Error::InsufficientFunds(format!("Need {} mojos", required)))?;

    let funding_coin = Coin::new(
        Bytes32::new(funding_coin_old.parent_coin_info.to_bytes()),
        Bytes32::new(funding_coin_old.puzzle_hash.to_bytes()),
        funding_coin_old.amount,
    );

    // =========================================================================
    // STEP 1: Create singleton with test_action action layer
    // =========================================================================
    println!();
    println!("{}", style("--- Step 1: Creating Singleton with Test Action ---").yellow().bold());

    let ctx = &mut SpendContext::new();

    let launcher = Launcher::new(funding_coin.coin_id(), singleton_amount);
    let launcher_id = launcher.coin().coin_id();

    println!("  Launcher ID: 0x{}", hex::encode(launcher_id.to_bytes()));

    let inner_hash_bytes32: Bytes32 = action_layer_inner_hash.into();

    let (launcher_conditions, singleton_coin) = launcher
        .spend(ctx, inner_hash_bytes32, ())
        .map_err(|e| Error::Transaction(format!("Launcher spend failed: {:?}", e)))?;

    println!("  Singleton coin ID: 0x{}", hex::encode(singleton_coin.coin_id().to_bytes()));
    println!("  Singleton puzzle hash: 0x{}", hex::encode(singleton_coin.puzzle_hash.to_bytes()));

    // Build funding coin spend
    let change_after_create = funding_coin.amount - singleton_amount - fee;
    let mut conditions = launcher_conditions;

    if change_after_create > 0 {
        conditions = conditions.create_coin(wallet_puzzle_hash, change_after_create, chia::puzzles::Memos::None);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }

    standard_layer.spend(ctx, funding_coin.clone(), conditions)
        .map_err(|e| Error::Transaction(format!("Funding coin spend failed: {:?}", e)))?;

    // Sign and broadcast creation
    let coin_spends = ctx.take();
    println!("  Signing {} coin spend(s)...", coin_spends.len());

    let signature = sign_coin_spends(&coin_spends, &derived_sk, testnet)
        .map_err(|e| Error::Transaction(format!("Signing failed: {:?}", e)))?;

    let dl_spends = convert_spends_to_dl(&coin_spends);
    let dl_sig = DLSignature::from_bytes(&signature.to_bytes())
        .map_err(|_| Error::Transaction("Invalid signature bytes".to_string()))?;

    let bundle = SpendBundle::new(dl_spends, dl_sig);

    println!("  Broadcasting creation transaction...");
    let result = dl::broadcast_spend_bundle(&peer, bundle)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if result.status == 3 {
        let err = result.error.unwrap_or_default();
        return Err(Error::Transaction(format!("Broadcast failed: {}", err)));
    }

    // Wait for singleton confirmation
    let singleton_puzzle_hash_dl = Bytes32::new(singleton_coin.puzzle_hash.to_bytes());
    wait_for_coin_confirmation(
        &peer,
        singleton_puzzle_hash_dl,
        singleton_coin.coin_id(),
        genesis,
        "Singleton",
    ).await?;

    println!("  {} Singleton created!", style("✓").green().bold());

    // =========================================================================
    // STEP 2: Spend singleton using test_action (just increments state)
    // =========================================================================
    println!();
    println!("{}", style("--- Step 2: Spending Singleton with Test Action ---").yellow().bold());

    let ctx = &mut SpendContext::new();

    // Create the ActionLayer for spending
    let (action_layer, action_puzzle_hash) = create_test_action_layer(wallet_puzzle_hash, initial_state);
    println!("  Test action hash: 0x{}", hex::encode(action_puzzle_hash.to_bytes()));

    // Build the action layer inner puzzle
    let inner_puzzle_ptr = action_layer.construct_puzzle(ctx)
        .map_err(|e| Error::Transaction(format!("Failed to construct action layer puzzle: {:?}", e)))?;

    // Build the test_action puzzle (no currying needed - it's already complete)
    let test_action_bytes = get_test_action_bytes();
    let test_action_mod_hash = test_action_puzzle_hash();
    let test_action_puzzle = ctx.puzzle(test_action_mod_hash, &test_action_bytes)
        .map_err(|e| Error::Transaction(format!("Failed to load test_action: {:?}", e)))?;

    // The test_action solution is empty (it just uses state from action layer)
    let test_action_solution = ctx.alloc(&())
        .map_err(|e| Error::Transaction(format!("Failed to alloc action solution: {:?}", e)))?;

    // Get merkle proof for the action
    let action_hashes = vec![action_puzzle_hash];
    let proofs = action_layer.get_proofs(&action_hashes, &[action_puzzle_hash])
        .ok_or_else(|| Error::Transaction("Failed to get merkle proofs".to_string()))?;

    println!("  Merkle proofs: {}", proofs.len());

    // Build the action layer solution
    let action_layer_solution = ActionLayerSolution {
        proofs,
        action_spends: vec![Spend::new(test_action_puzzle, test_action_solution)],
        finalizer_solution: clvmr::NodePtr::NIL,
    };

    println!("  Building action layer solution...");
    let inner_solution = action_layer.construct_solution(ctx, action_layer_solution)
        .map_err(|e| Error::Transaction(format!("Failed to construct action layer solution: {:?}", e)))?;

    // Debug: print the inner puzzle and solution structures
    {
        let inner_puzzle_bytes: Vec<u8> = ctx.serialize(&inner_puzzle_ptr).map_err(|e| Error::Transaction(format!("{:?}", e)))?.into();
        let inner_solution_bytes: Vec<u8> = ctx.serialize(&inner_solution).map_err(|e| Error::Transaction(format!("{:?}", e)))?.into();
        println!("  Inner puzzle hex: {}", hex::encode(&inner_puzzle_bytes));
        println!("  Inner solution hex: {}", hex::encode(&inner_solution_bytes));

        // Test just the inner puzzle (action layer)
        let mut test_alloc = Allocator::new();
        let inner_puzzle_ptr_test = node_from_bytes(&mut test_alloc, &inner_puzzle_bytes).expect("valid puzzle");
        let inner_solution_ptr_test = node_from_bytes(&mut test_alloc, &inner_solution_bytes).expect("valid solution");

        println!("  Testing action layer puzzle directly...");
        match clvmr::run_program(
            &mut test_alloc,
            &clvmr::ChiaDialect::new(0),
            inner_puzzle_ptr_test,
            inner_solution_ptr_test,
            11_000_000_000,
        ) {
            Ok(reduction) => {
                println!("    {} Action layer puzzle test passed! cost={}", style("✓").green(), reduction.0);
            }
            Err(e) => {
                println!("    {} Action layer puzzle test FAILED: {:?}", style("✗").red(), e);
            }
        }
    }

    // Build singleton solution with eve proof
    let eve_proof = Proof::Eve(EveProof {
        parent_parent_coin_info: funding_coin.coin_id(),
        parent_amount: singleton_amount,
    });

    let singleton_solution = build_singleton_solution(ctx, eve_proof, singleton_coin.amount, inner_solution)
        .map_err(|e| Error::Transaction(format!("Failed to build singleton solution: {:?}", e)))?;

    // Build singleton puzzle
    let singleton_puzzle = build_singleton_puzzle(ctx, launcher_id, inner_puzzle_ptr)
        .map_err(|e| Error::Transaction(format!("Failed to build singleton puzzle: {:?}", e)))?;

    // Debug: Test the spend locally before broadcasting
    println!("  Testing puzzle locally...");
    {
        let puzzle_bytes: Vec<u8> = ctx.serialize(&singleton_puzzle).map_err(|e| Error::Transaction(format!("{:?}", e)))?.into();
        let solution_bytes: Vec<u8> = ctx.serialize(&singleton_solution).map_err(|e| Error::Transaction(format!("{:?}", e)))?.into();

        let mut test_alloc = Allocator::new();
        let puzzle_ptr = node_from_bytes(&mut test_alloc, &puzzle_bytes).expect("valid puzzle");
        let solution_ptr = node_from_bytes(&mut test_alloc, &solution_bytes).expect("valid solution");

        match clvmr::run_program(
            &mut test_alloc,
            &clvmr::ChiaDialect::new(0),
            puzzle_ptr,
            solution_ptr,
            11_000_000_000,
        ) {
            Ok(reduction) => {
                println!("    {} Local test passed! cost={}", style("✓").green(), reduction.0);
            }
            Err(e) => {
                println!("    {} Local test FAILED: {:?}", style("✗").red(), e);
                return Err(Error::Transaction(format!("Puzzle execution failed locally: {:?}", e)));
            }
        }
    }

    let singleton_spend = CoinSpend::new(
        singleton_coin.clone(),
        ctx.serialize(&singleton_puzzle).map_err(|e| Error::Transaction(format!("{:?}", e)))?,
        ctx.serialize(&singleton_solution).map_err(|e| Error::Transaction(format!("{:?}", e)))?,
    );

    ctx.insert(singleton_spend);

    // Add fee from change coin
    if fee > 0 && change_after_create >= fee {
        let fee_coin = Coin::new(
            funding_coin.coin_id(),
            wallet_puzzle_hash,
            change_after_create,
        );

        let change_after_spend = change_after_create - fee;
        let mut fee_conditions = Conditions::new().reserve_fee(fee);
        if change_after_spend > 0 {
            fee_conditions = fee_conditions.create_coin(wallet_puzzle_hash, change_after_spend, chia::puzzles::Memos::None);
        }

        standard_layer.spend(ctx, fee_coin, fee_conditions)
            .map_err(|e| Error::Transaction(format!("Fee coin spend failed: {:?}", e)))?;
    }

    // Sign and broadcast
    let coin_spends = ctx.take();
    println!("  Signing {} coin spend(s)...", coin_spends.len());

    let signature = sign_coin_spends(&coin_spends, &derived_sk, testnet)
        .map_err(|e| Error::Transaction(format!("Signing failed: {:?}", e)))?;

    let dl_spends = convert_spends_to_dl(&coin_spends);
    let dl_sig = DLSignature::from_bytes(&signature.to_bytes())
        .map_err(|_| Error::Transaction("Invalid signature bytes".to_string()))?;

    let bundle = SpendBundle::new(dl_spends, dl_sig);

    println!("  Broadcasting spend transaction...");
    let result = dl::broadcast_spend_bundle(&peer, bundle)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if result.status == 3 {
        let err = result.error.unwrap_or_default();
        return Err(Error::Transaction(format!("Broadcast failed: {}", err)));
    }

    // Compute the new singleton puzzle hash (state unchanged since test_action doesn't modify it)
    // The finalizer recreates with the same state, so puzzle hash should be the same
    let new_inner_hash = compute_test_action_layer_inner_hash(wallet_puzzle_hash, initial_state);
    let new_singleton_puzzle_hash: Bytes32 = SingletonArgs::curry_tree_hash(
        launcher_id,
        new_inner_hash,
    ).into();

    // Compute the new singleton coin ID
    let new_singleton_coin = Coin::new(
        singleton_coin.coin_id(),
        new_singleton_puzzle_hash,
        singleton_coin.amount,
    );

    println!("  New singleton puzzle hash: 0x{}", hex::encode(new_singleton_puzzle_hash.to_bytes()));
    println!("  New singleton coin ID: 0x{}", hex::encode(new_singleton_coin.coin_id().to_bytes()));

    // Wait for new singleton confirmation
    wait_for_coin_confirmation(
        &peer,
        new_singleton_puzzle_hash,
        new_singleton_coin.coin_id(),
        genesis,
        "New singleton",
    ).await?;

    // =========================================================================
    // Done!
    // =========================================================================
    println!();
    println!("{}", style("=== TEST COMPLETE ===").green().bold());
    println!();
    println!("  Launcher ID: 0x{}", hex::encode(launcher_id.to_bytes()));
    println!("  State: unchanged (passthrough test)");
    println!("  Action layer test: {}", style("PASSED").green().bold());
    println!();
    println!("The simplest action layer pattern works!");

    Ok(())
}

/// Test the emit_child_action - creates singleton, spends it to emit a child singleton
async fn test_emit_child_action(testnet: bool, wallet_name: &str, fee: u64, password: Option<String>) -> Result<()> {
    use dialoguer::Password;
    use chia_wallet_sdk::driver::ActionLayerSolution;

    let singleton_amount: u64 = 1;
    let child_singleton_amount: u64 = 1;

    println!("{}", style("=== TEST EMIT CHILD ACTION ===").cyan().bold());
    println!("Network: {}", if testnet { "testnet" } else { "mainnet" });
    println!("Pattern: Action Layer with emit_child_action (creates child singleton)");
    println!();

    // Load wallet
    let wallet_path = get_wallet_dir()?.join(format!("{}.wallet", wallet_name));
    if !wallet_path.exists() {
        return Err(Error::WalletNotFound(wallet_name.to_string()));
    }

    let passphrase = match password {
        Some(p) => p,
        None => Password::new()
            .with_prompt("Enter wallet passphrase")
            .interact()
            .map_err(|e| Error::Config(e.to_string()))?,
    };

    let master_sk = load_encrypted_wallet(&wallet_path, &passphrase)?;

    let derived_sk = master_sk
        .derive_hardened(12381)
        .derive_hardened(8444)
        .derive_hardened(2)
        .derive_unhardened(0);
    let derived_pk = derived_sk.public_key();

    let standard_layer = StandardLayer::new(derived_pk.clone());
    let wallet_puzzle_hash: Bytes32 = standard_layer.tree_hash().into();

    // Initial state - must be proper cons cell (counter . marker)
    let initial_state = TestState { counter: 1, marker: 0xDEADBEEF };
    let action_layer_inner_hash = compute_emit_child_action_layer_inner_hash(wallet_puzzle_hash, initial_state);
    println!("  Emit child action puzzle hash: 0x{}", hex::encode(emit_child_action_puzzle_hash().to_bytes()));
    println!("  Action layer inner hash: 0x{}", hex::encode(action_layer_inner_hash.to_bytes()));

    // Connect to network
    let peer = connect_peer(testnet).await?;
    let genesis = get_genesis_challenge(testnet);

    // Get wallet coins
    let puzzle_hash_tree = StandardArgs::curry_tree_hash(derived_pk.clone());
    let puzzle_hash_dl = Bytes32::new(puzzle_hash_tree.to_bytes());

    let coins = dl::get_all_unspent_coins(&peer, puzzle_hash_dl, None, genesis)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if coins.coin_states.is_empty() {
        return Err(Error::InsufficientFunds("No coins in wallet".to_string()));
    }

    // Need: singleton (1) + child singleton (1) + 2 fees
    let required = singleton_amount + child_singleton_amount + fee * 2;
    let funding_coin_old = coins.coin_states.iter()
        .find(|cs| cs.coin.amount >= required)
        .map(|cs| &cs.coin)
        .ok_or_else(|| Error::InsufficientFunds(format!("Need {} mojos", required)))?;

    let funding_coin = Coin::new(
        Bytes32::new(funding_coin_old.parent_coin_info.to_bytes()),
        Bytes32::new(funding_coin_old.puzzle_hash.to_bytes()),
        funding_coin_old.amount,
    );

    // =========================================================================
    // STEP 1: Create singleton with emit_child action layer
    // =========================================================================
    println!();
    println!("{}", style("--- Step 1: Creating Singleton with Emit Child Action ---").yellow().bold());

    let ctx = &mut SpendContext::new();

    let launcher = Launcher::new(funding_coin.coin_id(), singleton_amount);
    let launcher_id = launcher.coin().coin_id();

    println!("  Launcher ID: 0x{}", hex::encode(launcher_id.to_bytes()));

    let inner_hash_bytes32: Bytes32 = action_layer_inner_hash.into();

    let (launcher_conditions, singleton_coin) = launcher
        .spend(ctx, inner_hash_bytes32, ())
        .map_err(|e| Error::Transaction(format!("Launcher spend failed: {:?}", e)))?;

    println!("  Singleton coin ID: 0x{}", hex::encode(singleton_coin.coin_id().to_bytes()));
    println!("  Singleton puzzle hash: 0x{}", hex::encode(singleton_coin.puzzle_hash.to_bytes()));

    // Build funding coin spend
    let change_after_create = funding_coin.amount - singleton_amount - fee;
    let mut conditions = launcher_conditions;

    if change_after_create > 0 {
        conditions = conditions.create_coin(wallet_puzzle_hash, change_after_create, chia::puzzles::Memos::None);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }

    standard_layer.spend(ctx, funding_coin.clone(), conditions)
        .map_err(|e| Error::Transaction(format!("Funding coin spend failed: {:?}", e)))?;

    // Sign and broadcast creation
    let coin_spends = ctx.take();
    println!("  Signing {} coin spend(s)...", coin_spends.len());

    let signature = sign_coin_spends(&coin_spends, &derived_sk, testnet)
        .map_err(|e| Error::Transaction(format!("Signing failed: {:?}", e)))?;

    let dl_spends = convert_spends_to_dl(&coin_spends);
    let dl_sig = DLSignature::from_bytes(&signature.to_bytes())
        .map_err(|_| Error::Transaction("Invalid signature bytes".to_string()))?;

    let bundle = SpendBundle::new(dl_spends, dl_sig);

    println!("  Broadcasting creation transaction...");
    let result = dl::broadcast_spend_bundle(&peer, bundle)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if result.status == 3 {
        let err = result.error.unwrap_or_default();
        return Err(Error::Transaction(format!("Broadcast failed: {}", err)));
    }

    // Wait for singleton confirmation
    let singleton_puzzle_hash_dl = Bytes32::new(singleton_coin.puzzle_hash.to_bytes());
    wait_for_coin_confirmation(
        &peer,
        singleton_puzzle_hash_dl,
        singleton_coin.coin_id(),
        genesis,
        "Singleton",
    ).await?;

    println!("  {} Singleton created!", style("✓").green().bold());

    // =========================================================================
    // STEP 2: Spend singleton using emit_child_action to spawn child
    // =========================================================================
    println!();
    println!("{}", style("--- Step 2: Emitting Child via Action Layer ---").yellow().bold());

    let ctx = &mut SpendContext::new();

    // The child launcher will be created by the emit_child action with amount 0
    let child_launcher_coin = Coin::new(
        singleton_coin.coin_id(),
        Bytes32::new(SINGLETON_LAUNCHER_PUZZLE_HASH),
        0,
    );
    let child_launcher_id = child_launcher_coin.coin_id();

    println!("  Child launcher ID: 0x{}", hex::encode(child_launcher_id.to_bytes()));

    // Compute the child singleton puzzle hash using SDK
    let child_hash = child_inner_puzzle_hash();
    let sdk_child_singleton_hash: Bytes32 = SingletonArgs::curry_tree_hash(child_launcher_id, child_hash).into();
    println!("  Child singleton puzzle hash: 0x{}", hex::encode(sdk_child_singleton_hash.to_bytes()));

    // Create the ActionLayer for spending
    let (action_layer, action_puzzle_hash) = create_emit_child_action_layer(wallet_puzzle_hash, initial_state);
    println!("  Action puzzle hash: 0x{}", hex::encode(action_puzzle_hash.to_bytes()));

    // Build the action layer inner puzzle
    let inner_puzzle_ptr = action_layer.construct_puzzle(ctx)
        .map_err(|e| Error::Transaction(format!("Failed to construct action layer puzzle: {:?}", e)))?;

    // Build the emit_child action puzzle (uncurried)
    let emit_action_puzzle = build_emit_child_action_puzzle(ctx)
        .map_err(|e| Error::Transaction(format!("Failed to build emit_child action: {:?}", e)))?;

    // Build the action solution: (my_coin_id . child_puzzle_hash)
    let emit_action_solution = EmitChildActionSolution {
        my_singleton_coin_id: singleton_coin.coin_id(),
        child_singleton_puzzle_hash: sdk_child_singleton_hash,
    };
    let emit_action_solution_ptr = ctx.alloc(&emit_action_solution)
        .map_err(|e| Error::Transaction(format!("Failed to alloc action solution: {:?}", e)))?;

    // Get merkle proof for the action
    let proofs = action_layer.get_proofs(&[action_puzzle_hash], &[action_puzzle_hash])
        .ok_or_else(|| Error::Transaction("Failed to get merkle proofs".to_string()))?;

    println!("  Merkle proofs: {}", proofs.len());

    // Build the action layer solution
    let action_layer_solution = ActionLayerSolution {
        proofs,
        action_spends: vec![Spend::new(emit_action_puzzle, emit_action_solution_ptr)],
        finalizer_solution: clvmr::NodePtr::NIL,
    };

    println!("  Building action layer solution...");
    let inner_solution = action_layer.construct_solution(ctx, action_layer_solution)
        .map_err(|e| Error::Transaction(format!("Failed to construct action layer solution: {:?}", e)))?;

    // Test action layer puzzle directly
    {
        let inner_puzzle_bytes: Vec<u8> = ctx.serialize(&inner_puzzle_ptr).map_err(|e| Error::Transaction(format!("{:?}", e)))?.into();
        let inner_solution_bytes: Vec<u8> = ctx.serialize(&inner_solution).map_err(|e| Error::Transaction(format!("{:?}", e)))?.into();

        let mut test_alloc = Allocator::new();
        let inner_puzzle_ptr_test = node_from_bytes(&mut test_alloc, &inner_puzzle_bytes).expect("valid puzzle");
        let inner_solution_ptr_test = node_from_bytes(&mut test_alloc, &inner_solution_bytes).expect("valid solution");

        println!("  Testing action layer puzzle...");
        match clvmr::run_program(
            &mut test_alloc,
            &clvmr::ChiaDialect::new(0),
            inner_puzzle_ptr_test,
            inner_solution_ptr_test,
            11_000_000_000,
        ) {
            Ok(reduction) => {
                println!("    {} Action layer puzzle OK! cost={}", style("✓").green(), reduction.0);
            }
            Err(e) => {
                println!("    {} Action layer puzzle FAILED: {:?}", style("✗").red(), e);
                return Err(Error::Transaction(format!("Puzzle execution failed: {:?}", e)));
            }
        }
    }

    // Build singleton solution with eve proof
    let eve_proof = Proof::Eve(EveProof {
        parent_parent_coin_info: funding_coin.coin_id(),
        parent_amount: singleton_amount,
    });

    let singleton_solution = build_singleton_solution(ctx, eve_proof, singleton_coin.amount, inner_solution)
        .map_err(|e| Error::Transaction(format!("Failed to build singleton solution: {:?}", e)))?;

    // Build singleton puzzle
    let singleton_puzzle = build_singleton_puzzle(ctx, launcher_id, inner_puzzle_ptr)
        .map_err(|e| Error::Transaction(format!("Failed to build singleton puzzle: {:?}", e)))?;

    // Test full singleton spend locally
    println!("  Testing full singleton spend locally...");
    {
        let puzzle_bytes: Vec<u8> = ctx.serialize(&singleton_puzzle).map_err(|e| Error::Transaction(format!("{:?}", e)))?.into();
        let solution_bytes: Vec<u8> = ctx.serialize(&singleton_solution).map_err(|e| Error::Transaction(format!("{:?}", e)))?.into();

        let mut test_alloc = Allocator::new();
        let puzzle_ptr = node_from_bytes(&mut test_alloc, &puzzle_bytes).expect("valid puzzle");
        let solution_ptr = node_from_bytes(&mut test_alloc, &solution_bytes).expect("valid solution");

        match clvmr::run_program(
            &mut test_alloc,
            &clvmr::ChiaDialect::new(0),
            puzzle_ptr,
            solution_ptr,
            11_000_000_000,
        ) {
            Ok(reduction) => {
                println!("    {} Singleton test passed! cost={}", style("✓").green(), reduction.0);
            }
            Err(e) => {
                println!("    {} Singleton test FAILED: {:?}", style("✗").red(), e);
                return Err(Error::Transaction(format!("Puzzle execution failed locally: {:?}", e)));
            }
        }
    }

    let singleton_spend = CoinSpend::new(
        singleton_coin.clone(),
        ctx.serialize(&singleton_puzzle).map_err(|e| Error::Transaction(format!("{:?}", e)))?,
        ctx.serialize(&singleton_solution).map_err(|e| Error::Transaction(format!("{:?}", e)))?,
    );

    ctx.insert(singleton_spend);

    // Spend child launcher to create child singleton (0-amount launcher -> 1 mojo singleton)
    // The funding comes from the wallet, not the launcher
    println!("  Spending child launcher...");
    let (_child_launcher_conds, child_singleton) = Launcher::from_coin(child_launcher_coin.clone(), Conditions::new())
        .with_singleton_amount(child_singleton_amount)
        .mint_vault(ctx, child_hash, ())
        .map_err(|e| Error::Transaction(format!("Child launcher mint_vault failed: {:?}", e)))?;

    println!("  Child singleton ID: 0x{}", hex::encode(child_singleton.coin.coin_id().to_bytes()));
    println!("  Child singleton puzzle hash: 0x{}", hex::encode(child_singleton.coin.puzzle_hash.to_bytes()));

    // Fund child singleton and pay fee
    let total_needed = child_singleton_amount + fee;
    if change_after_create >= total_needed {
        let fee_coin = Coin::new(
            funding_coin.coin_id(),
            wallet_puzzle_hash,
            change_after_create,
        );

        let change_after_spend = change_after_create - total_needed;
        let mut fee_conditions = Conditions::new();
        if fee > 0 {
            fee_conditions = fee_conditions.reserve_fee(fee);
        }
        // Create coin for child singleton funding
        fee_conditions = fee_conditions.create_coin(
            child_singleton.coin.puzzle_hash,
            0, // Amount comes from launcher, but we assert it
            chia::puzzles::Memos::None,
        );
        if change_after_spend > 0 {
            fee_conditions = fee_conditions.create_coin(wallet_puzzle_hash, change_after_spend, chia::puzzles::Memos::None);
        }

        standard_layer.spend(ctx, fee_coin, fee_conditions)
            .map_err(|e| Error::Transaction(format!("Fee coin spend failed: {:?}", e)))?;
    } else {
        return Err(Error::InsufficientFunds(format!(
            "Need {} mojos for child + fee, have {}",
            total_needed, change_after_create
        )));
    }

    // Sign and broadcast
    let coin_spends = ctx.take();
    println!("  Signing {} coin spend(s)...", coin_spends.len());

    let signature = sign_coin_spends(&coin_spends, &derived_sk, testnet)
        .map_err(|e| Error::Transaction(format!("Signing failed: {:?}", e)))?;

    let dl_spends = convert_spends_to_dl(&coin_spends);
    let dl_sig = DLSignature::from_bytes(&signature.to_bytes())
        .map_err(|_| Error::Transaction("Invalid signature bytes".to_string()))?;

    let bundle = SpendBundle::new(dl_spends, dl_sig);

    println!("  Broadcasting emit child transaction...");
    let result = dl::broadcast_spend_bundle(&peer, bundle)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if result.status == 3 {
        let err = result.error.unwrap_or_default();
        return Err(Error::Transaction(format!("Broadcast failed: {}", err)));
    }

    // Compute the new parent singleton puzzle hash (state incremented)
    let new_state = TestState { counter: initial_state.counter + 1, marker: initial_state.marker };
    let new_inner_hash = compute_emit_child_action_layer_inner_hash(wallet_puzzle_hash, new_state);
    let new_singleton_puzzle_hash: Bytes32 = SingletonArgs::curry_tree_hash(
        launcher_id,
        new_inner_hash,
    ).into();

    let new_singleton_coin = Coin::new(
        singleton_coin.coin_id(),
        new_singleton_puzzle_hash,
        singleton_coin.amount,
    );

    println!("  New parent singleton ID: 0x{}", hex::encode(new_singleton_coin.coin_id().to_bytes()));

    // Wait for confirmations
    wait_for_coin_confirmation(
        &peer,
        new_singleton_puzzle_hash,
        new_singleton_coin.coin_id(),
        genesis,
        "New parent singleton",
    ).await?;

    wait_for_coin_confirmation(
        &peer,
        child_singleton.coin.puzzle_hash,
        child_singleton.coin.coin_id(),
        genesis,
        "Child singleton",
    ).await?;

    // =========================================================================
    // Done!
    // =========================================================================
    println!();
    println!("{}", style("=== EMIT CHILD TEST COMPLETE ===").green().bold());
    println!();
    println!("  Parent launcher ID: 0x{}", hex::encode(launcher_id.to_bytes()));
    println!("  Child launcher ID: 0x{}", hex::encode(child_launcher_id.to_bytes()));
    println!("  State: counter incremented from {} to {}", initial_state.counter, new_state.counter);
    println!("  Emit child action test: {}", style("PASSED").green().bold());
    println!();
    println!("Action layer successfully spawned a child singleton!");

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

async fn connect_peer(testnet: bool) -> Result<datalayer_driver::Peer> {
    use datalayer_driver::NetworkType;
    use tokio::time::{timeout, Duration};

    let network_type = if testnet { NetworkType::Testnet11 } else { NetworkType::Mainnet };

    println!("  Connecting to peer...");

    for attempt in 1..=5 {
        print!("  Attempt {}/5: ", attempt);
        std::io::Write::flush(&mut std::io::stdout()).ok();

        match timeout(
            Duration::from_secs(30),
            dl::connect_random(network_type.clone(), "wallet_node.crt", "wallet_node.key")
        ).await {
            Ok(Ok(peer)) => {
                println!("{}", style("connected").green());
                return Ok(peer);
            }
            Ok(Err(e)) => {
                println!("{} ({:?})", style("failed").red(), e);
                if attempt < 5 {
                    println!("    Retrying in 3 seconds...");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
            Err(_) => {
                println!("{}", style("timeout").yellow());
                if attempt < 5 {
                    println!("    Retrying in 3 seconds...");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
        }
    }

    Err(Error::Network("Failed to connect after 5 attempts".to_string()))
}

fn get_genesis_challenge(testnet: bool) -> Bytes32 {
    use datalayer_driver::constants;
    if testnet {
        constants::get_testnet11_genesis_challenge()
    } else {
        constants::get_mainnet_genesis_challenge()
    }
}

async fn wait_for_coin_confirmation(
    peer: &datalayer_driver::Peer,
    puzzle_hash: Bytes32,
    expected_coin_id: Bytes32,
    genesis: Bytes32,
    coin_name: &str,
) -> Result<()> {
    use tokio::time::{Duration, Instant, timeout};

    let start = Instant::now();
    let timeout_duration = Duration::from_secs(300);
    let poll_interval = Duration::from_secs(5);
    let request_timeout = Duration::from_secs(30);

    println!("  Waiting for {} confirmation...", coin_name);

    let mut consecutive_errors = 0;
    const MAX_CONSECUTIVE_ERRORS: u32 = 10;

    loop {
        if start.elapsed() > timeout_duration {
            return Err(Error::Transaction(format!(
                "Timeout waiting for {} confirmation after 5 minutes",
                coin_name
            )));
        }

        // Wrap the RPC call in a timeout to prevent hangs
        let result = timeout(
            request_timeout,
            dl::get_all_unspent_coins(peer, puzzle_hash, None, genesis)
        ).await;

        match result {
            Ok(Ok(coins)) => {
                consecutive_errors = 0; // Reset error counter on success
                for cs in &coins.coin_states {
                    let coin_id_bytes = Bytes32::new(expected_coin_id.to_bytes());
                    let this_coin_id = Bytes32::new(
                        chia_protocol::Coin::new(
                            cs.coin.parent_coin_info,
                            cs.coin.puzzle_hash,
                            cs.coin.amount,
                        ).coin_id().to_bytes()
                    );
                    if this_coin_id == coin_id_bytes {
                        let elapsed = start.elapsed().as_secs();
                        println!(
                            "\n  {} {} confirmed in {}s",
                            style("✓").green().bold(),
                            coin_name,
                            elapsed
                        );
                        return Ok(());
                    }
                }
            }
            Ok(Err(e)) => {
                consecutive_errors += 1;
                tracing::debug!("Poll error: {:?}", e);
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    return Err(Error::Network(format!(
                        "Too many consecutive errors while waiting for {}: {:?}",
                        coin_name, e
                    )));
                }
            }
            Err(_) => {
                // Timeout occurred
                consecutive_errors += 1;
                tracing::debug!("Request timeout while polling for {}", coin_name);
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    return Err(Error::Network(format!(
                        "Too many timeouts while waiting for {} confirmation",
                        coin_name
                    )));
                }
            }
        }

        let elapsed = start.elapsed().as_secs();
        print!(
            "\r  {} Waiting for confirmation... {}s elapsed   ",
            style("⏳").yellow(),
            elapsed
        );
        std::io::Write::flush(&mut std::io::stdout()).ok();

        tokio::time::sleep(poll_interval).await;
    }
}

fn sign_coin_spends(
    coin_spends: &[CoinSpend],
    secret_key: &chia::bls::SecretKey,
    testnet: bool,
) -> std::result::Result<chia::bls::Signature, Box<dyn std::error::Error + Send + Sync>> {
    use chia::bls::sign;
    use std::collections::HashMap;

    let constants = if testnet {
        AggSigConstants::from(&*TESTNET11_CONSTANTS)
    } else {
        AggSigConstants::from(&*MAINNET_CONSTANTS)
    };

    let mut allocator = Allocator::new();
    let required = RequiredSignature::from_coin_spends(&mut allocator, coin_spends, &constants)?;

    let pk = secret_key.public_key();
    let keys: HashMap<_, _> = [(pk.clone(), secret_key)].into_iter().collect();

    let mut sigs = Vec::new();
    for req in required {
        match req {
            RequiredSignature::Bls(bls) => {
                if let Some(sk) = keys.get(&bls.public_key) {
                    sigs.push(sign(sk, bls.message()));
                }
            }
            RequiredSignature::Secp(_) => {
                return Err("SECP not supported".into());
            }
        }
    }

    Ok(sigs.into_iter().fold(chia::bls::Signature::default(), |a, b| a + &b))
}

fn convert_spends_to_dl(spends: &[CoinSpend]) -> Vec<CoinSpend> {
    spends.iter().map(|cs| {
        CoinSpend::new(
            Coin::new(
                Bytes32::new(cs.coin.parent_coin_info.to_bytes()),
                Bytes32::new(cs.coin.puzzle_hash.to_bytes()),
                cs.coin.amount,
            ),
            Vec::<u8>::from(cs.puzzle_reveal.clone()).into(),
            Vec::<u8>::from(cs.solution.clone()).into(),
        )
    }).collect()
}

fn get_wallet_dir() -> Result<PathBuf> {
    let dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("puzzle_tests")
        .join("wallets");
    Ok(dir)
}

fn generate_mnemonic() -> Result<String> {
    use bip39::{Language, Mnemonic};
    use rand::RngCore;

    let mut entropy = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);

    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| Error::Config(format!("Failed to generate mnemonic: {}", e)))?;

    Ok(mnemonic.to_string())
}

fn save_encrypted_wallet(path: &PathBuf, secret_key: &chia::bls::SecretKey, passphrase: &str) -> Result<()> {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let key: [u8; 32] = hasher.finalize().into();

    let sk_bytes = secret_key.to_bytes();
    let encrypted: Vec<u8> = sk_bytes.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % 32])
        .collect();

    std::fs::write(path, encrypted)?;
    Ok(())
}

fn load_encrypted_wallet(path: &PathBuf, passphrase: &str) -> Result<chia::bls::SecretKey> {
    use sha2::{Sha256, Digest};

    let encrypted = std::fs::read(path)?;

    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let key: [u8; 32] = hasher.finalize().into();

    let decrypted: Vec<u8> = encrypted.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % 32])
        .collect();

    let sk_bytes: [u8; 32] = decrypted.try_into()
        .map_err(|_| Error::InvalidPassphrase)?;

    chia::bls::SecretKey::from_bytes(&sk_bytes)
        .map_err(|_| Error::InvalidPassphrase)
}

fn compute_puzzle_hash(public_key: &chia::bls::PublicKey) -> [u8; 32] {
    StandardArgs::curry_tree_hash(public_key.clone()).to_bytes()
}

fn compute_address(public_key: &chia::bls::PublicKey) -> String {
    let puzzle_hash = compute_puzzle_hash(public_key);
    let hrp = bech32::Hrp::parse("xch").expect("valid hrp");
    bech32::encode::<bech32::Bech32m>(hrp, &puzzle_hash).expect("valid encoding")
}

// ============================================================================
// Offline Test Function - Tests action layer puzzle without network
// ============================================================================

fn run_offline_test() -> Result<()> {
    use clvmr::SExp;
    use chia_wallet_sdk::driver::ActionLayerSolution;

    println!("{}", style("=== OFFLINE ACTION LAYER TEST ===").cyan().bold());
    println!("This test runs entirely offline to debug action layer puzzle execution.");
    println!();

    // Create a fake wallet puzzle hash (just some bytes for hint)
    let fake_wallet_hash = Bytes32::new([0x42; 32]);
    // IMPORTANT: Use TestState (proper cons cell) to avoid "path into atom" errors
    let initial_state = TestState { counter: 1, marker: 0xDEADBEEF };

    // =========================================================================
    // Test 1: test_action puzzle directly
    // =========================================================================
    println!("{}", style("--- Test 1: test_action puzzle directly ---").yellow().bold());

    let mut allocator = Allocator::new();

    let test_action_bytes = get_test_action_bytes();
    let test_action_mod = node_from_bytes(&mut allocator, &test_action_bytes).expect("valid puzzle");
    let test_action_hash = chia::clvm_utils::tree_hash(&allocator, test_action_mod);
    println!("  test_action hash: 0x{}", hex::encode(test_action_hash.to_bytes()));

    // test_action takes (state) as input, returns ((state+1, nil), [])
    // Use state=1 not 0 because 0 is nil in CLVM
    let state_1 = allocator.new_number(1.into()).unwrap();
    let nil = allocator.nil();
    let test_sol = allocator.new_pair(state_1, nil).unwrap(); // (1)

    match clvmr::run_program(
        &mut allocator,
        &clvmr::ChiaDialect::new(0),
        test_action_mod,
        test_sol,
        11_000_000_000,
    ) {
        Ok(reduction) => {
            println!("  {} test_action direct: cost={}", style("OK").green().bold(), reduction.0);
            let result_bytes = clvmr::serde::node_to_bytes(&allocator, reduction.1).unwrap();
            println!("  result hex: {}", hex::encode(&result_bytes));
        }
        Err(e) => {
            println!("  {} test_action direct: {:?}", style("FAIL").red().bold(), e);
            return Err(Error::Transaction(format!("test_action failed: {:?}", e)));
        }
    }

    // =========================================================================
    // Test 2: ActionLayer with test_action
    // =========================================================================
    println!();
    println!("{}", style("--- Test 2: ActionLayer with test_action ---").yellow().bold());

    let test_action_hash_bytes: Bytes32 = test_action_hash.into();
    let finalizer: Finalizer<()> = Finalizer::Default { hint: fake_wallet_hash };
    let action_layer = ActionLayer::from_action_puzzle_hashes(
        &[test_action_hash_bytes],
        initial_state,
        finalizer,
    );

    let ctx = &mut SpendContext::new();

    // Build action layer puzzle
    let al_puzzle_ptr = action_layer.construct_puzzle(ctx)
        .map_err(|e| Error::Transaction(format!("construct_puzzle failed: {:?}", e)))?;

    let al_puzzle_bytes: Vec<u8> = ctx.serialize(&al_puzzle_ptr)
        .map_err(|e| Error::Transaction(format!("{:?}", e)))?
        .into();
    println!("  Action layer puzzle: {} bytes", al_puzzle_bytes.len());

    // Build action layer solution
    let test_action_puzzle_ptr = ctx.puzzle(test_action_hash, &test_action_bytes)
        .map_err(|e| Error::Transaction(format!("Failed to load puzzle: {:?}", e)))?;

    // test_action takes NO additional args, just state (which action layer provides)
    let empty_solution = ctx.alloc(&()).map_err(|e| Error::Transaction(format!("{:?}", e)))?;

    let proofs = action_layer.get_proofs(&[test_action_hash_bytes], &[test_action_hash_bytes])
        .ok_or_else(|| Error::Transaction("Failed to get proofs".to_string()))?;

    println!("  Got {} merkle proof(s)", proofs.len());
    for (i, p) in proofs.iter().enumerate() {
        println!("    Proof {}: path={}, proof_hashes={}", i, p.path, p.proof.len());
    }

    let al_solution = ActionLayerSolution {
        proofs,
        action_spends: vec![Spend::new(test_action_puzzle_ptr, empty_solution)],
        finalizer_solution: clvmr::NodePtr::NIL,
    };

    let al_solution_ptr = action_layer.construct_solution(ctx, al_solution)
        .map_err(|e| Error::Transaction(format!("construct_solution failed: {:?}", e)))?;

    let al_solution_bytes: Vec<u8> = ctx.serialize(&al_solution_ptr)
        .map_err(|e| Error::Transaction(format!("{:?}", e)))?
        .into();
    println!("  Action layer solution: {} bytes", al_solution_bytes.len());
    println!("  Solution hex: {}", hex::encode(&al_solution_bytes));

    // Parse solution structure
    let mut test_alloc = Allocator::new();
    let al_sol_parsed = node_from_bytes(&mut test_alloc, &al_solution_bytes).unwrap();

    println!("  Parsing solution structure (expecting: puzzles selectors_and_proofs solutions finalizer_sol)...");
    match test_alloc.sexp(al_sol_parsed) {
        SExp::Pair(puzzles, rest1) => {
            let puz_bytes = clvmr::serde::node_to_bytes(&test_alloc, puzzles).unwrap();
            println!("    puzzles: {} bytes", puz_bytes.len());

            match test_alloc.sexp(rest1) {
                SExp::Pair(sel_proofs, rest2) => {
                    let sp_bytes = clvmr::serde::node_to_bytes(&test_alloc, sel_proofs).unwrap();
                    println!("    selectors_and_proofs: {} bytes = {}", sp_bytes.len(), hex::encode(&sp_bytes));

                    match test_alloc.sexp(rest2) {
                        SExp::Pair(solutions, rest3) => {
                            let sol_bytes = clvmr::serde::node_to_bytes(&test_alloc, solutions).unwrap();
                            println!("    solutions: {} bytes = {}", sol_bytes.len(), hex::encode(&sol_bytes));

                            match test_alloc.sexp(rest3) {
                                SExp::Pair(fin_sol, _) => {
                                    let fin_bytes = clvmr::serde::node_to_bytes(&test_alloc, fin_sol).unwrap();
                                    println!("    finalizer_solution: {} bytes = {}", fin_bytes.len(), hex::encode(&fin_bytes));
                                }
                                SExp::Atom => println!("    rest3 is atom (no finalizer_solution)"),
                            }
                        }
                        SExp::Atom => println!("    rest2 is atom"),
                    }
                }
                SExp::Atom => println!("    rest1 is atom"),
            }
        }
        SExp::Atom => println!("    solution is atom (unexpected)"),
    }

    // Run action layer puzzle with solution
    let al_puzzle_parsed = node_from_bytes(&mut test_alloc, &al_puzzle_bytes).unwrap();

    println!("  Running action layer puzzle...");
    match clvmr::run_program(
        &mut test_alloc,
        &clvmr::ChiaDialect::new(0),
        al_puzzle_parsed,
        al_sol_parsed,
        11_000_000_000,
    ) {
        Ok(reduction) => {
            println!("  {} Action layer execution: cost={}", style("OK").green().bold(), reduction.0);
            let result_bytes = clvmr::serde::node_to_bytes(&test_alloc, reduction.1).unwrap();
            println!("  result hex: {}", hex::encode(&result_bytes));
        }
        Err(e) => {
            println!("  {} Action layer execution: {:?}", style("FAIL").red().bold(), e);
        }
    }

    // =========================================================================
    // Test 2.5: emit_child_action puzzle directly (uncurried)
    // =========================================================================
    println!();
    println!("{}", style("--- Test 2.5: emit_child_action puzzle directly ---").yellow().bold());

    let mut emit_direct_alloc = Allocator::new();

    // Load emit_child_action mod (uncurried)
    let emit_action_bytes = get_emit_child_action_bytes();
    let emit_action_mod = node_from_bytes(&mut emit_direct_alloc, &emit_action_bytes).expect("valid puzzle");
    let emit_mod_hash = chia::clvm_utils::tree_hash(&emit_direct_alloc, emit_action_mod);
    println!("  emit_child_action mod hash: 0x{}", hex::encode(emit_mod_hash.to_bytes()));

    // Build state as TestState structure: (ephemeral . (counter . marker))
    let nil = emit_direct_alloc.nil();
    let marker = emit_direct_alloc.new_number(0xDEADBEEFu64.into()).unwrap();
    let counter = emit_direct_alloc.new_number(1.into()).unwrap();
    let persistent = emit_direct_alloc.new_pair(counter, marker).unwrap();
    let state = emit_direct_alloc.new_pair(nil, persistent).unwrap();

    // Build solution: (my_coin_id . child_hash) - cons pair not list
    let fake_coin_id_direct = Bytes32::from([0x11u8; 32]);
    let fake_child_hash_direct = Bytes32::from([0x22u8; 32]);
    let coin_id_atom = emit_direct_alloc.new_atom(&fake_coin_id_direct.to_bytes()).unwrap();
    let child_hash_atom = emit_direct_alloc.new_atom(&fake_child_hash_direct.to_bytes()).unwrap();
    let solution = emit_direct_alloc.new_pair(coin_id_atom, child_hash_atom).unwrap();

    // Build env: (state . solution)
    let direct_env = emit_direct_alloc.new_pair(state, solution).unwrap();

    // Print env hex for debugging
    let direct_env_hex = clvmr::serde::node_to_bytes(&emit_direct_alloc, direct_env).unwrap();
    println!("  Direct env: {} bytes", direct_env_hex.len());

    println!("  Running emit_child_action directly...");
    match clvmr::run_program(
        &mut emit_direct_alloc,
        &clvmr::ChiaDialect::new(0),
        emit_action_mod,
        direct_env,
        11_000_000_000,
    ) {
        Ok(reduction) => {
            println!("  {} emit_child_action direct: cost={}", style("OK").green().bold(), reduction.0);
            let result_bytes = clvmr::serde::node_to_bytes(&emit_direct_alloc, reduction.1).unwrap();
            println!("  result hex (first 100): {}", hex::encode(&result_bytes[..std::cmp::min(100, result_bytes.len())]));
        }
        Err(e) => {
            println!("  {} emit_child_action direct: {:?}", style("FAIL").red().bold(), e);
        }
    }

    // =========================================================================
    // Test 3: ActionLayer with emit_child_action
    // =========================================================================
    println!();
    println!("{}", style("--- Test 3: ActionLayer with emit_child_action ---").yellow().bold());

    // Create action layer with emit_child (using uncurried hash)
    let emit_hash: Bytes32 = emit_child_action_puzzle_hash().into();
    println!("  emit_child mod hash: 0x{}", hex::encode(emit_hash.to_bytes()));

    let emit_finalizer: Finalizer<()> = Finalizer::Default { hint: fake_wallet_hash };
    let emit_action_layer: ActionLayer<TestState> = ActionLayer::from_action_puzzle_hashes(
        &[emit_hash],
        initial_state, // state = TestState { counter: 1, marker: 0xDEADBEEF }
        emit_finalizer,
    );

    let emit_ctx = &mut SpendContext::new();

    // Build action layer puzzle
    let emit_al_puzzle_ptr = emit_action_layer.construct_puzzle(emit_ctx)
        .map_err(|e| Error::Transaction(format!("construct_puzzle failed: {:?}", e)))?;

    let emit_al_puzzle_bytes: Vec<u8> = emit_ctx.serialize(&emit_al_puzzle_ptr)
        .map_err(|e| Error::Transaction(format!("{:?}", e)))?
        .into();
    println!("  Action layer puzzle: {} bytes", emit_al_puzzle_bytes.len());

    // Build the curried emit_child puzzle
    let emit_puzzle_ptr = build_emit_child_action_puzzle(emit_ctx)
        .map_err(|e| Error::Transaction(format!("build_emit_child failed: {:?}", e)))?;

    // Create a fake solution for testing
    let fake_coin_id = Bytes32::from([0x11u8; 32]);
    let fake_child_hash = Bytes32::from([0x22u8; 32]);
    let emit_sol = EmitChildActionSolution {
        my_singleton_coin_id: fake_coin_id,
        child_singleton_puzzle_hash: fake_child_hash,
    };
    let emit_sol_ptr = emit_ctx.alloc(&emit_sol)
        .map_err(|e| Error::Transaction(format!("Failed to alloc solution: {:?}", e)))?;

    // Debug: print the action solution
    let emit_sol_bytes: Vec<u8> = emit_ctx.serialize(&emit_sol_ptr)
        .map_err(|e| Error::Transaction(format!("{:?}", e)))?
        .into();
    println!("  Action solution: {} bytes = {}", emit_sol_bytes.len(), hex::encode(&emit_sol_bytes));

    // Get proofs
    let emit_proofs = emit_action_layer.get_proofs(&[emit_hash], &[emit_hash])
        .ok_or_else(|| Error::Transaction("Failed to get proofs".to_string()))?;

    println!("  Got {} merkle proof(s)", emit_proofs.len());
    for (i, p) in emit_proofs.iter().enumerate() {
        println!("    Proof {}: path={}, proof_hashes={}", i, p.path, p.proof.len());
    }

    // Build action layer solution
    let emit_al_solution = ActionLayerSolution {
        proofs: emit_proofs,
        action_spends: vec![Spend::new(emit_puzzle_ptr, emit_sol_ptr)],
        finalizer_solution: clvmr::NodePtr::NIL,
    };

    let emit_al_solution_ptr = emit_action_layer.construct_solution(emit_ctx, emit_al_solution)
        .map_err(|e| Error::Transaction(format!("construct_solution failed: {:?}", e)))?;

    let emit_al_solution_bytes: Vec<u8> = emit_ctx.serialize(&emit_al_solution_ptr)
        .map_err(|e| Error::Transaction(format!("{:?}", e)))?
        .into();
    println!("  Action layer solution: {} bytes", emit_al_solution_bytes.len());
    println!("  Solution hex (first 100): {}", hex::encode(&emit_al_solution_bytes[..std::cmp::min(100, emit_al_solution_bytes.len())]));

    // Parse solution to verify structure
    let mut emit_test_alloc = Allocator::new();
    let emit_al_sol_parsed = node_from_bytes(&mut emit_test_alloc, &emit_al_solution_bytes).unwrap();
    let emit_al_puzzle_parsed = node_from_bytes(&mut emit_test_alloc, &emit_al_puzzle_bytes).unwrap();

    println!("  Parsing solution structure...");
    match emit_test_alloc.sexp(emit_al_sol_parsed) {
        SExp::Pair(puzzles, rest1) => {
            let puz_bytes = clvmr::serde::node_to_bytes(&emit_test_alloc, puzzles).unwrap();
            println!("    puzzles: {} bytes", puz_bytes.len());

            match emit_test_alloc.sexp(rest1) {
                SExp::Pair(sel_proofs, rest2) => {
                    let sp_bytes = clvmr::serde::node_to_bytes(&emit_test_alloc, sel_proofs).unwrap();
                    println!("    selectors_and_proofs: {} bytes", sp_bytes.len());

                    match emit_test_alloc.sexp(rest2) {
                        SExp::Pair(solutions, rest3) => {
                            let sol_bytes = clvmr::serde::node_to_bytes(&emit_test_alloc, solutions).unwrap();
                            println!("    solutions: {} bytes", sol_bytes.len());

                            match emit_test_alloc.sexp(rest3) {
                                SExp::Pair(fin_sol, _) => {
                                    let fin_bytes = clvmr::serde::node_to_bytes(&emit_test_alloc, fin_sol).unwrap();
                                    println!("    finalizer_solution: {} bytes", fin_bytes.len());
                                }
                                SExp::Atom => println!("    rest3 is atom (no finalizer_solution)"),
                            }
                        }
                        SExp::Atom => println!("    rest2 is atom"),
                    }
                }
                SExp::Atom => println!("    rest1 is atom"),
            }
        }
        SExp::Atom => println!("    solution is atom (unexpected)"),
    }

    // Run action layer puzzle with emit_child solution
    println!("  Running action layer puzzle with emit_child...");
    match clvmr::run_program(
        &mut emit_test_alloc,
        &clvmr::ChiaDialect::new(0),
        emit_al_puzzle_parsed,
        emit_al_sol_parsed,
        11_000_000_000,
    ) {
        Ok(reduction) => {
            println!("  {} ActionLayer with emit_child: cost={}", style("OK").green().bold(), reduction.0);
            let result_bytes = clvmr::serde::node_to_bytes(&emit_test_alloc, reduction.1).unwrap();
            println!("  result hex (first 100): {}", hex::encode(&result_bytes[..std::cmp::min(100, result_bytes.len())]));
        }
        Err(e) => {
            println!("  {} ActionLayer with emit_child: {:?}", style("FAIL").red().bold(), e);
        }
    }

    println!();
    println!("{}", style("=== OFFLINE TEST COMPLETE ===").cyan().bold());

    Ok(())
}
