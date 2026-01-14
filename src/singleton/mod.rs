//! Singleton management for Action Layer singletons
//!
//! This module provides the core infrastructure for working with CHIP-0050
//! Action Layer singletons:
//!
//! - [`SingletonDriver`] - Core driver for singleton lifecycle management
//! - [`SingletonCoin`] - Tracks an on-chain singleton
//! - [`SingletonLineage`] - Lineage information for proof generation
//! - [`SpendOptions`] - Options for spend bundle handling and broadcast
//!
//! # Helper Functions
//!
//! For backward compatibility and advanced use cases, standalone helper functions
//! are also available:
//! - [`create_eve_proof`], [`create_lineage_proof`] - Proof creation
//! - [`spawn_child_singleton`] - Child singleton spawning
//! - [`singleton_puzzle_hash`], [`child_singleton_puzzle_hash`] - Hash computation

mod driver;
mod helpers;
mod spend_options;
mod types;

// Core driver and types
pub use driver::{SingletonDriver, SINGLETON_LAUNCHER_PUZZLE_HASH};
pub use spend_options::{FeeOptions, SpendOptions};
pub use types::{
    ActionSpendResult, LaunchResult, Melted, NoOutput, SingletonCoin, SingletonLineage,
};

// Helper functions (for backward compatibility and advanced use)
pub use helpers::{
    // Low-level puzzle building
    build_singleton_puzzle,
    build_singleton_solution,
    // Puzzle hash computation
    child_singleton_puzzle_hash,
    // Proof creation
    create_eve_proof,
    create_lineage_proof,
    create_singleton_coin_spend,
    expected_child_launcher_id,
    launch_singleton,
    singleton_puzzle_hash,
    // Child spawning
    spawn_child_singleton,
    ChildLaunchResult,
};
