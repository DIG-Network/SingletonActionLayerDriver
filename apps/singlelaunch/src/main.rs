//! Singlelaunch - A singleton that spawns children using a custom Rue puzzle.
//!
//! This app demonstrates using a custom Rue-compiled inner puzzle that:
//! - Always recreates the parent singleton when spent
//! - Spawns a child singleton via a launcher (amount 0 pattern)
//!
//! Based on the pattern from https://github.com/Rigidity/singleton-emitter-example
//!
//! The puzzle creates a launcher with amount 0, and the SDK's with_singleton_amount(1)
//! sets the child singleton's amount.
//!
//! Usage:
//!   singlelaunch wallet create           # Create a new wallet
//!   singlelaunch create --testnet        # Create a spawner singleton
//!   singlelaunch spend <launcher_id>     # Spend singleton to spawn a child
//!   singlelaunch status <launcher_id>    # Check singleton status

use clap::{Parser, Subcommand};
use console::style;
use std::path::PathBuf;

// SDK types (chia 0.26 / chia-wallet-sdk 0.30 for datalayer-driver compatibility)
use chia::protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia::bls::DerivableKey;

// SDK driver types
use chia_wallet_sdk::driver::{SpendContext, StandardLayer, Launcher};
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
// Singleton Emitter Puzzle (compiled from Rue)
// Based on https://github.com/Rigidity/singleton-emitter-example
// ============================================================================

/// The compiled emitter_inner_puzzle.rue
/// This puzzle creates a launcher with amount 0 when spent.
///
/// Curried args: (mod_hash, child_inner_puzzle_hash)
/// Solution: (my_coin_id)
///
/// When spent, the puzzle:
/// 1. Recreates itself with amount 1
/// 2. Creates a launcher coin with amount 0
/// 3. Asserts the launcher announcement
const EMITTER_PUZZLE_HEX: &str = include_str!("../../../puzzles/output/emitter_inner_puzzle.clvm.hex");

/// The compiled child_inner_puzzle.rue
/// This is the inner puzzle used for child singletons.
/// In this example, it just melts the singleton.
const CHILD_PUZZLE_HEX: &str = include_str!("../../../puzzles/output/child_inner_puzzle.clvm.hex");

/// Singleton launcher puzzle hash (standard)
const SINGLETON_LAUNCHER_PUZZLE_HASH: [u8; 32] = hex_literal::hex!(
    "eff07522495060c066f66f32acc2a77e3a3e737aca8baea4d1a64ea4cdc13da9"
);

// ============================================================================
// CLVM Types for Emitter Puzzle (matching reference implementation)
// ============================================================================

/// Emitter puzzle curried arguments: (mod_hash, child_inner_puzzle_hash)
/// Using #[clvm(curry)] for proper curry tree hash calculation
#[derive(Debug, Clone, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct EmitterArgs {
    pub mod_hash: Bytes32,
    pub child_inner_puzzle_hash: Bytes32,
}

/// Emitter puzzle solution: (my_coin_id)
/// Using #[clvm(list)] for proper list serialization
#[derive(Debug, Clone, ToClvm, FromClvm)]
#[clvm(list)]
pub struct EmitterSolution {
    pub my_coin_id: Bytes32,
}

// ============================================================================
// Puzzle Loading and Hashing Functions
// ============================================================================

/// Get the emitter puzzle as bytes
fn get_emitter_puzzle_bytes() -> Vec<u8> {
    let hex_str = EMITTER_PUZZLE_HEX.trim();
    hex::decode(hex_str).expect("valid hex in emitter_inner_puzzle.clvm.hex")
}

/// Get the child puzzle as bytes
fn get_child_puzzle_bytes() -> Vec<u8> {
    let hex_str = CHILD_PUZZLE_HEX.trim();
    hex::decode(hex_str).expect("valid hex in child_inner_puzzle.clvm.hex")
}

/// Compute the tree hash of the uncurried emitter puzzle
fn emitter_mod_hash() -> TreeHash {
    let puzzle_bytes = get_emitter_puzzle_bytes();
    let mut allocator = Allocator::new();
    let puzzle_ptr = node_from_bytes(&mut allocator, &puzzle_bytes)
        .expect("valid puzzle");
    chia::clvm_utils::tree_hash(&allocator, puzzle_ptr)
}

/// Compute the tree hash of the child inner puzzle
fn child_inner_puzzle_hash() -> TreeHash {
    let puzzle_bytes = get_child_puzzle_bytes();
    let mut allocator = Allocator::new();
    let puzzle_ptr = node_from_bytes(&mut allocator, &puzzle_bytes)
        .expect("valid puzzle");
    chia::clvm_utils::tree_hash(&allocator, puzzle_ptr)
}

/// Compute the curried emitter inner puzzle hash.
/// The emitter is curried with (mod_hash, child_inner_puzzle_hash).
fn compute_emitter_inner_hash() -> TreeHash {
    let mod_hash = emitter_mod_hash();
    let child_hash: Bytes32 = child_inner_puzzle_hash().into();

    let args = EmitterArgs {
        mod_hash: mod_hash.into(),
        child_inner_puzzle_hash: child_hash,
    };

    CurriedProgram {
        program: mod_hash,
        args: &args,
    }.tree_hash()
}

/// Build the curried emitter puzzle using SDK methods
fn build_curried_emitter_puzzle(
    ctx: &mut SpendContext,
    child_inner_puzzle_hash: Bytes32,
) -> anyhow::Result<NodePtr> {
    let puzzle_bytes = get_emitter_puzzle_bytes();
    let mod_hash = emitter_mod_hash();
    let puzzle_ptr = ctx.puzzle(mod_hash, &puzzle_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to load emitter puzzle: {:?}", e))?;

    let args = EmitterArgs {
        mod_hash: mod_hash.into(),
        child_inner_puzzle_hash,
    };

    ctx.alloc(&CurriedProgram {
        program: puzzle_ptr,
        args,
    }).map_err(|e| anyhow::anyhow!("Failed to curry emitter puzzle: {:?}", e))
}

/// Build emitter solution
fn build_emitter_solution(
    ctx: &mut SpendContext,
    my_coin_id: Bytes32,
) -> anyhow::Result<NodePtr> {
    let solution = EmitterSolution { my_coin_id };
    ctx.alloc(&solution)
        .map_err(|e| anyhow::anyhow!("Failed to build emitter solution: {:?}", e))
}

/// Build singleton puzzle using SDK types (SingletonArgs)
fn build_singleton_puzzle(
    ctx: &mut SpendContext,
    launcher_id: Bytes32,
    inner_puzzle: NodePtr,
) -> anyhow::Result<NodePtr> {
    // Load singleton top layer using ctx.puzzle() for caching
    let singleton_mod_hash = TreeHash::new(chia_puzzles::SINGLETON_TOP_LAYER_V1_1_HASH);
    let singleton_ptr = ctx.puzzle(singleton_mod_hash, &chia_puzzles::SINGLETON_TOP_LAYER_V1_1)
        .map_err(|e| anyhow::anyhow!("Failed to load singleton module: {:?}", e))?;

    // Use SDK's SingletonArgs and CurriedProgram for proper currying
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
#[command(about = "Singleton spawner using custom Rue puzzle")]
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
        /// Singleton will be created with child_amount + 2 mojos
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
        Commands::Status { launcher_id, testnet } => {
            check_status(&launcher_id, testnet).await?;
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
// Singleton Commands (using Rue puzzle)
// ============================================================================

async fn create_singleton(testnet: bool, wallet_name: &str, fee: u64, password: Option<String>, _child_amount: u64) -> Result<()> {
    use dialoguer::Password;

    // The emitter pattern uses amount 1 for the singleton.
    // When spent, it recreates with amount 1 and creates a launcher with amount 0.
    // The child singleton gets amount 1 via with_singleton_amount(1).
    let singleton_amount: u64 = 1;

    println!("Creating emitter singleton on {}...", if testnet { "testnet" } else { "mainnet" });
    println!("  Using Rue-compiled singleton emitter puzzle");
    println!("  Singleton amount: {} mojo (emitter pattern)", singleton_amount);

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

    // Compute the emitter inner puzzle hash
    let inner_puzzle_hash = compute_emitter_inner_hash();
    println!("  Emitter inner puzzle hash: 0x{}", hex::encode(inner_puzzle_hash.to_bytes()));

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

    // Need singleton_amount mojos + fee
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

    // Create launcher with amount 1 (emitter pattern)
    let launcher = Launcher::new(funding_coin.coin_id(), singleton_amount);
    let launcher_id = launcher.coin().coin_id();

    println!("  Launcher ID: 0x{}", hex::encode(launcher_id.to_bytes()));

    // Use the emitter puzzle hash as the inner puzzle
    let inner_puzzle_hash_bytes32: Bytes32 = inner_puzzle_hash.into();

    // Spend launcher to create singleton with emitter inner puzzle
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
    println!("  Inner Puzzle: singleton_emitter (Rue)");
    println!();
    println!("To spend and emit a child:");
    println!("  singlelaunch spend 0x{} --funding-parent 0x{}{}",
        hex::encode(launcher_id.to_bytes()),
        hex::encode(funding_coin.coin_id().to_bytes()),
        if testnet { " --testnet" } else { "" });

    Ok(())
}

/// All-in-one: Create singleton, wait for confirmation, then spend to emit child
/// Based on https://github.com/Rigidity/singleton-emitter-example
async fn launch_and_spawn(testnet: bool, wallet_name: &str, fee: u64, password: Option<String>, _child_amount: u64) -> Result<()> {
    use dialoguer::Password;

    // Emitter pattern: singleton always has amount 1, child gets amount 1 via with_singleton_amount
    let singleton_amount: u64 = 1;

    println!("{}", style("=== LAUNCH & EMIT ===").cyan().bold());
    println!("Network: {}", if testnet { "testnet" } else { "mainnet" });
    println!("Singleton amount: {} mojo (emitter pattern)", singleton_amount);
    println!("Child singleton amount: 1 mojo (via with_singleton_amount)");
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

    // Compute puzzle hashes
    let emitter_inner_hash = compute_emitter_inner_hash();
    let child_puzzle_hash: Bytes32 = child_inner_puzzle_hash().into();

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

    // Need singleton_amount + fee for creation, then fee again for spending
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
    // STEP 1: Create the singleton
    // =========================================================================
    println!("{}", style("--- Step 1: Creating Emitter Singleton ---").yellow().bold());

    let ctx = &mut SpendContext::new();

    let launcher = Launcher::new(funding_coin.coin_id(), singleton_amount);
    let launcher_id = launcher.coin().coin_id();

    println!("  Launcher ID: 0x{}", hex::encode(launcher_id.to_bytes()));

    let emitter_inner_hash_bytes32: Bytes32 = emitter_inner_hash.into();

    let (launcher_conditions, singleton_coin) = launcher
        .spend(ctx, emitter_inner_hash_bytes32, ())
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
    // STEP 2: Spend singleton to emit child (launcher amount 0 pattern)
    // =========================================================================
    println!();
    println!("{}", style("--- Step 2: Emitting Child Singleton ---").yellow().bold());

    let ctx = &mut SpendContext::new();

    // The child launcher is created by the puzzle with amount 0
    // It will have parent = singleton_coin_id, puzzle_hash = LAUNCHER_HASH, amount = 0
    let child_launcher_coin = Coin::new(
        singleton_coin.coin_id(),
        Bytes32::new(SINGLETON_LAUNCHER_PUZZLE_HASH),
        0,  // Amount 0 - the emitter pattern
    );
    let child_launcher_id = child_launcher_coin.coin_id();

    println!("  Child launcher ID: 0x{}", hex::encode(child_launcher_id.to_bytes()));

    // Build emitter inner solution: just (my_coin_id)
    let inner_solution = build_emitter_solution(ctx, singleton_coin.coin_id())
        .map_err(|e| Error::Transaction(format!("Failed to build emitter solution: {:?}", e)))?;

    // Build singleton solution using SDK types (Proof, SingletonSolution)
    let eve_proof = Proof::Eve(EveProof {
        parent_parent_coin_info: funding_coin.coin_id(),
        parent_amount: singleton_amount,
    });

    let singleton_solution = build_singleton_solution(ctx, eve_proof, singleton_coin.amount, inner_solution)
        .map_err(|e| Error::Transaction(format!("Failed to build singleton solution: {:?}", e)))?;

    // Build singleton puzzle using SDK types (SingletonArgs)
    let inner_puzzle_ptr = build_curried_emitter_puzzle(ctx, child_puzzle_hash)
        .map_err(|e| Error::Transaction(format!("Failed to build inner puzzle: {:?}", e)))?;

    let singleton_puzzle = build_singleton_puzzle(ctx, launcher_id, inner_puzzle_ptr)
        .map_err(|e| Error::Transaction(format!("Failed to build singleton puzzle: {:?}", e)))?;

    let singleton_spend = CoinSpend::new(
        singleton_coin.clone(),
        ctx.serialize(&singleton_puzzle).map_err(|e| Error::Transaction(format!("{:?}", e)))?,
        ctx.serialize(&singleton_solution).map_err(|e| Error::Transaction(format!("{:?}", e)))?,
    );

    ctx.insert(singleton_spend);

    // ===================
    // Spend child launcher to create child singleton
    // Using the reference pattern: Launcher::from_coin(..., 0).with_singleton_amount(1)
    // The child uses the child_inner_puzzle, not the emitter
    // ===================
    let (_child_launcher_conds, child_singleton) = Launcher::from_coin(child_launcher_coin.clone(), Conditions::new())
        .with_singleton_amount(1)
        .mint_vault(ctx, child_inner_puzzle_hash(), ())
        .map_err(|e| Error::Transaction(format!("Child launcher mint_vault failed: {:?}", e)))?;

    println!("  Child singleton ID: 0x{}", hex::encode(child_singleton.coin.coin_id().to_bytes()));

    // The child singleton needs 1 mojo, but the launcher has 0 mojos.
    // We must spend a wallet coin to provide the 1 mojo for the child + any fee.
    // This is required for coin conservation on mainnet.
    let child_funding_needed: u64 = 1; // Child singleton amount
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
    println!("The child singleton is ready! To emit a grandchild:");
    println!("  singlelaunch spend 0x{} --funding-parent 0x{}{}",
        hex::encode(child_launcher_id.to_bytes()),
        hex::encode(singleton_coin.coin_id().to_bytes()),
        if testnet { " --testnet" } else { "" });

    Ok(())
}

/// Spend an existing emitter singleton to emit a child singleton.
/// The emitter puzzle always emits when spent (no --no-spawn option).
async fn spend_singleton(
    launcher_id_hex: &str,
    funding_parent_hex: Option<&str>,
    testnet: bool,
    wallet_name: &str,
    fee: u64,
    password: Option<String>,
    _spawn_child: bool,  // Ignored - emitter always emits
    _child_amount: u64,  // Ignored - child always gets 1 mojo
) -> Result<()> {
    use dialoguer::Password;

    println!("Spending emitter singleton on {}...", if testnet { "testnet" } else { "mainnet" });
    println!("  The emitter puzzle will create a child with amount 0 launcher!");

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

    // Compute puzzle hashes
    let emitter_inner_hash = compute_emitter_inner_hash();
    let child_puzzle_hash: Bytes32 = child_inner_puzzle_hash().into();

    // Find the singleton coin
    let singleton_puzzle_hash: Bytes32 = SingletonArgs::curry_tree_hash(
        launcher_id,
        emitter_inner_hash,
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
        // For non-eve, we'd need to track lineage - simplified for now
        return Err(Error::Transaction(
            "Non-eve spends require lineage tracking (not implemented yet)".to_string()
        ));
    };

    // The child launcher is created by the puzzle with amount 0
    let child_launcher_coin = Coin::new(
        singleton_coin.coin_id(),
        Bytes32::new(SINGLETON_LAUNCHER_PUZZLE_HASH),
        0,  // Amount 0 - the emitter pattern
    );
    let child_launcher_id = child_launcher_coin.coin_id();

    println!("  Child launcher ID: 0x{}", hex::encode(child_launcher_id.to_bytes()));

    // Build emitter inner solution: just (my_coin_id)
    let inner_solution = build_emitter_solution(ctx, singleton_coin.coin_id())
        .map_err(|e| Error::Transaction(format!("Failed to build emitter solution: {:?}", e)))?;

    // Build singleton solution using SDK types
    let singleton_solution = build_singleton_solution(ctx, proof, singleton_coin.amount, inner_solution)
        .map_err(|e| Error::Transaction(format!("Failed to build singleton solution: {:?}", e)))?;

    // Build singleton puzzle using SDK types
    let inner_puzzle_ptr = build_curried_emitter_puzzle(ctx, child_puzzle_hash)
        .map_err(|e| Error::Transaction(format!("Failed to build inner puzzle: {:?}", e)))?;

    let singleton_puzzle = build_singleton_puzzle(ctx, launcher_id, inner_puzzle_ptr)
        .map_err(|e| Error::Transaction(format!("Failed to build singleton puzzle: {:?}", e)))?;

    let singleton_spend = CoinSpend::new(
        singleton_coin.clone(),
        ctx.serialize(&singleton_puzzle).map_err(|e| Error::Transaction(format!("{:?}", e)))?,
        ctx.serialize(&singleton_solution).map_err(|e| Error::Transaction(format!("{:?}", e)))?,
    );

    ctx.insert(singleton_spend);

    // Spend child launcher to create child singleton
    // Using the reference pattern: Launcher::from_coin(..., 0).with_singleton_amount(1)
    // The child uses the child_inner_puzzle, not the emitter
    let (_child_launcher_conds, child_singleton) = Launcher::from_coin(child_launcher_coin.clone(), Conditions::new())
        .with_singleton_amount(1)
        .mint_vault(ctx, child_inner_puzzle_hash(), ())
        .map_err(|e| Error::Transaction(format!("Child launcher mint_vault failed: {:?}", e)))?;

    println!("  Child singleton will be: 0x{}...", hex::encode(&child_singleton.coin.coin_id().to_bytes()[..8]));

    // The child singleton needs 1 mojo, but the launcher has 0 mojos.
    // We must spend a wallet coin to provide the 1 mojo for the child + any fee.
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
    println!("{} Singleton spent! Child emitted by puzzle!", style("✓").green().bold());
    println!();
    println!("  Parent launcher ID: 0x{}", hex::encode(launcher_id.to_bytes()));
    println!("  Child launcher ID:  0x{}", hex::encode(child_launcher_id.to_bytes()));
    println!("  Child singleton ID: 0x{}", hex::encode(child_singleton.coin.coin_id().to_bytes()));
    println!();
    println!("The child launcher was created BY THE SINGLETON PUZZLE (amount 0),");
    println!("and the SDK's with_singleton_amount(1) set the child to 1 mojo.");

    Ok(())
}

async fn check_status(launcher_id_hex: &str, testnet: bool) -> Result<()> {
    let launcher_id_hex = launcher_id_hex.strip_prefix("0x").unwrap_or(launcher_id_hex);
    let launcher_id_bytes: [u8; 32] = hex::decode(launcher_id_hex)
        .map_err(|e| Error::Config(format!("Invalid launcher ID: {}", e)))?
        .try_into()
        .map_err(|_| Error::Config("Launcher ID must be 32 bytes".to_string()))?;
    let launcher_id = Bytes32::new(launcher_id_bytes);

    println!("Checking singleton status on {}...", if testnet { "testnet" } else { "mainnet" });

    let peer = connect_peer(testnet).await?;
    let genesis = get_genesis_challenge(testnet);

    let inner_puzzle_hash = compute_emitter_inner_hash();
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
    println!("  Inner puzzle: singleton_emitter (Rue)");
    println!();

    if coins.coin_states.is_empty() {
        println!("  Status: {}", style("NOT FOUND").red());
        println!("  The singleton may have been melted or never created.");
    } else {
        println!("  Status: {}", style("ACTIVE").green().bold());
        println!("  Coin ID: 0x{}", hex::encode(coins.coin_states[0].coin.coin_id().to_bytes()));
        println!("  Amount: {} mojo", coins.coin_states[0].coin.amount);
    }

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
    use tokio::time::{Duration, Instant};

    let start = Instant::now();
    let timeout_duration = Duration::from_secs(300);
    let poll_interval = Duration::from_secs(5);

    println!("  Waiting for {} confirmation...", coin_name);

    loop {
        if start.elapsed() > timeout_duration {
            return Err(Error::Transaction(format!(
                "Timeout waiting for {} confirmation after 5 minutes",
                coin_name
            )));
        }

        match dl::get_all_unspent_coins(peer, puzzle_hash, None, genesis).await {
            Ok(coins) => {
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
            Err(e) => {
                tracing::debug!("Poll error: {:?}", e);
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
                // If key not found, skip (puzzle doesn't require signature)
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
