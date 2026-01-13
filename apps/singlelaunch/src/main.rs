//! Singlelaunch - Two Action Layer Demo (CHIP-0050)
//!
//! Demonstrates an Action Layer singleton with TWO curried emit_child actions.
//! Each action spawns a child singleton with a different inner puzzle.
//!
//! Usage:
//!   singlelaunch wallet create           # Create a new wallet
//!   singlelaunch two-actions             # Run the two-action test on mainnet

mod driver;

use clap::{Parser, Subcommand};
use console::style;
use std::path::PathBuf;

use chia::protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia::bls::DerivableKey;

use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
use chia_wallet_sdk::types::{Conditions, MAINNET_CONSTANTS, TESTNET11_CONSTANTS};
use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};

use clvm_utils::ToTreeHash;
use clvmr::Allocator;

use datalayer_driver::Signature as DLSignature;
use datalayer_driver::async_api as dl;

use driver::{
    TwoActionConfig, ActionState,
    create_singleton_spend, build_emit_child_spend,
    create_eve_proof, create_lineage_proof,
};

type StandardArgs = chia::puzzles::standard::StandardArgs;

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "singlelaunch")]
#[command(about = "Two Action Layer Demo (CHIP-0050)")]
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

    /// Run two-action test: creates singleton with 2 actions, spawns 2 children
    TwoActions {
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
        Commands::TwoActions { testnet, wallet, fee, password } => {
            test_two_actions(testnet, &wallet, fee, password).await?;
        }
    }

    Ok(())
}

// ============================================================================
// Two Actions Test
// ============================================================================

async fn test_two_actions(testnet: bool, wallet_name: &str, fee: u64, password: Option<String>) -> Result<()> {
    use dialoguer::Password;

    let singleton_amount: u64 = 1;

    println!("{}", style("=== TWO ACTIONS TEST ===").cyan().bold());
    println!("Network: {}", if testnet { "testnet" } else { "mainnet" });
    println!("Pattern: Action Layer with TWO curried emit_child actions");
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

    // Create action layer config
    let config = TwoActionConfig::new(wallet_puzzle_hash);
    let initial_state = ActionState::new(1, 0xDEADBEEF);

    println!("  Child inner 1: 0x{}...", &hex::encode(config.child_inner_1.to_bytes())[..16]);
    println!("  Child inner 2: 0x{}...", &hex::encode(config.child_inner_2.to_bytes())[..16]);

    // Connect
    let peer = connect_peer(testnet).await?;
    let genesis = get_genesis_challenge(testnet);

    // Get coins
    let puzzle_hash_tree = StandardArgs::curry_tree_hash(derived_pk.clone());
    let puzzle_hash_dl = Bytes32::new(puzzle_hash_tree.to_bytes());

    let coins = dl::get_all_unspent_coins(&peer, puzzle_hash_dl, None, genesis)
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if coins.coin_states.is_empty() {
        return Err(Error::InsufficientFunds("No coins in wallet".to_string()));
    }

    let required = singleton_amount + 2 + fee * 3; // singleton + 2 children + 3 fees
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
    // STEP 1: Create singleton with TWO actions
    // =========================================================================
    println!();
    println!("{}", style("--- Step 1: Create Singleton ---").yellow().bold());

    let ctx = &mut SpendContext::new();

    let (launcher_id, singleton_coin, launcher_conditions) = create_singleton_spend(
        ctx, &funding_coin, &config, initial_state, singleton_amount
    ).map_err(|e| Error::Transaction(format!("{:?}", e)))?;

    println!("  Launcher ID: 0x{}", hex::encode(launcher_id.to_bytes()));

    // Build funding coin spend with change
    let change_after_create = funding_coin.amount - singleton_amount - fee;
    let mut conditions = launcher_conditions;
    if change_after_create > 0 {
        conditions = conditions.create_coin(wallet_puzzle_hash, change_after_create, chia::puzzles::Memos::None);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }

    standard_layer.spend(ctx, funding_coin.clone(), conditions)
        .map_err(|e| Error::Transaction(format!("{:?}", e)))?;

    // Sign and broadcast
    let coin_spends = ctx.take();
    let signature = sign_coin_spends(&coin_spends, &derived_sk, testnet)
        .map_err(|e| Error::Transaction(format!("{:?}", e)))?;

    println!("  Broadcasting...");
    broadcast_bundle(&peer, &coin_spends, signature).await?;

    wait_for_coin_confirmation(&peer, singleton_coin.puzzle_hash, singleton_coin.coin_id(), genesis, "Singleton").await?;
    println!("  {} Singleton created!", style("OK").green().bold());

    // =========================================================================
    // STEP 2: Emit child 1 via action 1
    // =========================================================================
    println!();
    println!("{}", style("--- Step 2: Emit Child 1 ---").yellow().bold());

    let ctx = &mut SpendContext::new();

    let eve_proof = create_eve_proof(funding_coin.coin_id(), singleton_amount);

    let emit_result_1 = build_emit_child_spend(
        ctx, &singleton_coin, launcher_id, &config, initial_state, eve_proof, true
    ).map_err(|e| Error::Transaction(format!("{:?}", e)))?;

    println!("  Child 1 ID: 0x{}...", &hex::encode(emit_result_1.child_singleton.coin_id().to_bytes())[..16]);

    // Fund child and pay fee
    let fee_coin1 = Coin::new(funding_coin.coin_id(), wallet_puzzle_hash, change_after_create);
    let change_after_spend1 = change_after_create - 1 - fee;

    let mut fee_conditions1 = Conditions::new();
    if fee > 0 { fee_conditions1 = fee_conditions1.reserve_fee(fee); }
    fee_conditions1 = fee_conditions1.create_coin(emit_result_1.child_singleton.puzzle_hash, 0, chia::puzzles::Memos::None);
    if change_after_spend1 > 0 {
        fee_conditions1 = fee_conditions1.create_coin(wallet_puzzle_hash, change_after_spend1, chia::puzzles::Memos::None);
    }

    standard_layer.spend(ctx, fee_coin1.clone(), fee_conditions1)
        .map_err(|e| Error::Transaction(format!("{:?}", e)))?;

    // Sign and broadcast
    let coin_spends = ctx.take();
    let signature = sign_coin_spends(&coin_spends, &derived_sk, testnet)
        .map_err(|e| Error::Transaction(format!("{:?}", e)))?;

    println!("  Broadcasting...");
    broadcast_bundle(&peer, &coin_spends, signature).await?;

    wait_for_coin_confirmation(&peer, emit_result_1.new_parent_coin.puzzle_hash, emit_result_1.new_parent_coin.coin_id(), genesis, "Parent singleton").await?;
    wait_for_coin_confirmation(&peer, emit_result_1.child_singleton.puzzle_hash, emit_result_1.child_singleton.coin_id(), genesis, "Child 1").await?;
    println!("  {} Child 1 emitted!", style("OK").green().bold());

    // =========================================================================
    // STEP 3: Emit child 2 via action 2
    // =========================================================================
    println!();
    println!("{}", style("--- Step 3: Emit Child 2 ---").yellow().bold());

    let ctx = &mut SpendContext::new();

    let lineage_proof = create_lineage_proof(&singleton_coin, config.compute_inner_hash(initial_state));

    let emit_result_2 = build_emit_child_spend(
        ctx, &emit_result_1.new_parent_coin, launcher_id, &config, emit_result_1.new_state, lineage_proof, false
    ).map_err(|e| Error::Transaction(format!("{:?}", e)))?;

    println!("  Child 2 ID: 0x{}...", &hex::encode(emit_result_2.child_singleton.coin_id().to_bytes())[..16]);

    // Fund child and pay fee
    let fee_coin2 = Coin::new(fee_coin1.coin_id(), wallet_puzzle_hash, change_after_spend1);
    let change_after_spend2 = change_after_spend1 - 1 - fee;

    let mut fee_conditions2 = Conditions::new();
    if fee > 0 { fee_conditions2 = fee_conditions2.reserve_fee(fee); }
    fee_conditions2 = fee_conditions2.create_coin(emit_result_2.child_singleton.puzzle_hash, 0, chia::puzzles::Memos::None);
    if change_after_spend2 > 0 {
        fee_conditions2 = fee_conditions2.create_coin(wallet_puzzle_hash, change_after_spend2, chia::puzzles::Memos::None);
    }

    standard_layer.spend(ctx, fee_coin2, fee_conditions2)
        .map_err(|e| Error::Transaction(format!("{:?}", e)))?;

    // Sign and broadcast
    let coin_spends = ctx.take();
    let signature = sign_coin_spends(&coin_spends, &derived_sk, testnet)
        .map_err(|e| Error::Transaction(format!("{:?}", e)))?;

    println!("  Broadcasting...");
    broadcast_bundle(&peer, &coin_spends, signature).await?;

    wait_for_coin_confirmation(&peer, emit_result_2.new_parent_coin.puzzle_hash, emit_result_2.new_parent_coin.coin_id(), genesis, "Parent singleton").await?;
    wait_for_coin_confirmation(&peer, emit_result_2.child_singleton.puzzle_hash, emit_result_2.child_singleton.coin_id(), genesis, "Child 2").await?;
    println!("  {} Child 2 emitted!", style("OK").green().bold());

    // =========================================================================
    // Done!
    // =========================================================================
    println!();
    println!("{}", style("=== TEST COMPLETE ===").green().bold());
    println!();
    println!("  Parent launcher ID: 0x{}", hex::encode(launcher_id.to_bytes()));
    println!("  Child 1 launcher ID: 0x{}", hex::encode(emit_result_1.child_launcher_id.to_bytes()));
    println!("  Child 2 launcher ID: 0x{}", hex::encode(emit_result_2.child_launcher_id.to_bytes()));
    println!("  State: counter {} -> {}", initial_state.counter, emit_result_2.new_state.counter);
    println!();
    println!("Two actions successfully spawned two child singletons!");

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

    println!("{} Wallet created!", style("OK").green().bold());
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
// Network Helpers
// ============================================================================

async fn connect_peer(testnet: bool) -> Result<datalayer_driver::Peer> {
    use datalayer_driver::NetworkType;
    use tokio::time::{timeout, Duration};

    let network_type = if testnet { NetworkType::Testnet11 } else { NetworkType::Mainnet };

    println!("  Connecting...");

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
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
            Err(_) => {
                println!("{}", style("timeout").yellow());
                if attempt < 5 {
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

    println!("  Waiting for {} confirmation...", coin_name);

    loop {
        if start.elapsed() > timeout_duration {
            return Err(Error::Transaction(format!("Timeout waiting for {}", coin_name)));
        }

        let result = timeout(
            Duration::from_secs(30),
            dl::get_all_unspent_coins(peer, puzzle_hash, None, genesis)
        ).await;

        if let Ok(Ok(coins)) = result {
            for cs in &coins.coin_states {
                let this_coin_id = Bytes32::new(
                    chia_protocol::Coin::new(cs.coin.parent_coin_info, cs.coin.puzzle_hash, cs.coin.amount)
                        .coin_id().to_bytes()
                );
                if this_coin_id == expected_coin_id {
                    println!("\n  {} {} confirmed in {}s", style("OK").green().bold(), coin_name, start.elapsed().as_secs());
                    return Ok(());
                }
            }
        }

        print!("\r  Waiting... {}s   ", start.elapsed().as_secs());
        std::io::Write::flush(&mut std::io::stdout()).ok();
        tokio::time::sleep(poll_interval).await;
    }
}

async fn broadcast_bundle(
    peer: &datalayer_driver::Peer,
    coin_spends: &[CoinSpend],
    signature: chia::bls::Signature,
) -> Result<()> {
    let dl_spends = convert_spends_to_dl(coin_spends);
    let dl_sig = DLSignature::from_bytes(&signature.to_bytes())
        .map_err(|_| Error::Transaction("Invalid signature".to_string()))?;

    let result = dl::broadcast_spend_bundle(peer, SpendBundle::new(dl_spends, dl_sig))
        .await
        .map_err(|e| Error::Network(format!("{:?}", e)))?;

    if result.status == 3 {
        return Err(Error::Transaction(format!("Broadcast failed: {}", result.error.unwrap_or_default())));
    }

    Ok(())
}

// ============================================================================
// Signing & Serialization
// ============================================================================

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
            RequiredSignature::Secp(_) => return Err("SECP not supported".into()),
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

// ============================================================================
// Wallet Helpers
// ============================================================================

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
