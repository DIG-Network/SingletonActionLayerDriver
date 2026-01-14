# Action Layer Driver

A Rust library for building Action Layer (CHIP-0050) singleton spends on the Chia blockchain.

## Overview

The Action Layer is a pattern for Chia singletons that enables:

- **State Management**: Singletons that maintain and update state across spends
- **Action Dispatch**: Multiple actions (puzzles) that can be invoked via a merkle tree
- **Child Spawning**: Parent singletons that can create child singletons
- **Composable Patterns**: Building blocks for complex on-chain applications

This library provides a high-level Rust API for constructing Action Layer spends, handling proofs, and managing singleton lifecycle.

## Features

- `SingletonDriver<S>` - Generic driver for Action Layer singletons
- `PuzzleModule` - Load and curry CLVM puzzles with typed arguments
- `ActionLayerConfig` - Configure action merkle trees
- Automatic proof management (eve and lineage proofs)
- Child singleton spawning helpers
- Compatible with `chia-wallet-sdk` 0.30+

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
action-layer-driver = "0.1.0"
```

## Quick Start

```rust
use action_layer_driver::{SingletonDriver, PuzzleModule, LaunchResult};
use chia::protocol::{Bytes32, Coin};
use chia_wallet_sdk::driver::SpendContext;
use clvm_traits::{ToClvm, FromClvm};
use clvm_utils::ToTreeHash;

// 1. Define your state type
#[derive(Debug, Clone, ToClvm, FromClvm)]
#[clvm(list)]
pub struct MyState {
    pub counter: u64,
    #[clvm(rest)]
    pub data: Bytes32,
}

// 2. Compute action puzzle hashes
let action_hashes = vec![
    compute_action_1_hash(),
    compute_action_2_hash(),
];

// 3. Create driver with initial state
let initial_state = MyState { counter: 0, data: Bytes32::default() };
let mut driver = SingletonDriver::new(action_hashes, hint, initial_state);

// 4. Launch the singleton
let ctx = &mut SpendContext::new();
let result = driver.launch(ctx, &funding_coin, 1)?;
println!("Launched with ID: {}", hex::encode(result.launcher_id));

// 5. Build action spends
driver.build_action_spend(ctx, action_index, action_puzzle_ptr, solution_ptr)?;

// 6. Apply state after confirmation
driver.apply_spend(new_state);
```

## API Reference

### SingletonDriver<S>

The core driver for Action Layer singletons, generic over state type `S`.

```rust
// Create a new driver (not yet launched)
let driver = SingletonDriver::new(action_hashes, hint, initial_state);

// Create from existing on-chain singleton
let driver = SingletonDriver::from_coin(singleton_coin, state, action_hashes, hint);

// Launch the singleton
let result = driver.launch(ctx, funding_coin, amount)?;

// Build an action spend
driver.build_action_spend(ctx, action_index, action_puzzle, action_solution)?;

// Update state after confirmation
driver.apply_spend(new_state);

// Mark as melted (destroyed)
driver.mark_melted();

// Accessors
driver.launcher_id()         // Option<Bytes32>
driver.current_coin()        // Option<&Coin>
driver.state()               // &S
driver.proof()               // Option<Proof>
driver.inner_puzzle_hash()   // TreeHash
driver.expected_new_coin(&new_state)  // Option<Coin>
driver.expected_child_launcher_id()   // Option<Bytes32>
```

### PuzzleModule

Load and curry CLVM puzzles with typed arguments.

```rust
// Load from hex string
let module = PuzzleModule::from_hex(PUZZLE_HEX)?;

// Get module hash
let mod_hash = module.mod_hash();

// Curry with typed arguments
#[derive(ToClvm)]
#[clvm(curry)]
struct MyCurryArgs {
    pub field1: Bytes32,
    pub field2: u64,
}

let curried_ptr = module.curry_puzzle(ctx, MyCurryArgs { ... })?;
let curried_hash = module.curry_tree_hash(MyCurryArgs { ... });
```

### ActionLayerConfig

Configure action layer with merkle tree of action hashes.

```rust
let config = ActionLayerConfig::new(action_hashes, hint);

// Get inner puzzle hash for a state
let inner_hash = config.inner_puzzle_hash(&state);

// Build action spend (returns inner puzzle and solution)
let (inner_puzzle, inner_solution) = config.build_action_spend(
    ctx, state, action_index, action_puzzle, action_solution
)?;
```

### Helper Functions

```rust
// Proof creation
let eve_proof = create_eve_proof(launcher_parent_id, amount);
let lineage_proof = create_lineage_proof(&parent_coin, parent_inner_hash);

// Puzzle hash computation
let puzzle_hash = singleton_puzzle_hash(launcher_id, inner_hash);
let child_hash = child_singleton_puzzle_hash(child_launcher_id, child_inner_hash);
let child_id = expected_child_launcher_id(parent_coin_id);

// Child spawning
let result = spawn_child_singleton(ctx, parent_coin_id, child_inner_hash)?;
```

## Examples

### singlelaunch

Demonstrates a two-action singleton that spawns child singletons:

```bash
# Build the example
cargo build -p singlelaunch

# Show help
cargo run -p singlelaunch -- --help

# Create a wallet
cargo run -p singlelaunch -- wallet create

# Check balance
cargo run -p singlelaunch -- wallet balance

# Run the two-action test (requires funded wallet)
cargo run -p singlelaunch -- two-actions --password YOUR_PASSWORD
```

### wallet

A wallet management library for Chia L2 applications:

```bash
cargo build -p l2-wallet
```

## Puzzles

The library works with `Rue`-compiled puzzles. Example puzzles are in `puzzles/src/`:

- `emit_child_action.rue` - Action that spawns a child singleton
- `child_inner_puzzle.rue` - Inner puzzle for child type 1
- `child_inner_puzzle_2.rue` - Inner puzzle for child type 2
- `constants.rue` - Shared constants

To compile puzzles with `Rue`:

```bash
cd puzzles
rue build
```

Compiled outputs are in `puzzles/output/`.

## State Type Requirements

Your state type `S` must implement:

```rust
S: Clone + ToClvm<Allocator> + FromClvm<Allocator> + ToTreeHash
```

The easiest way is to derive these traits:

```rust
#[derive(Debug, Clone, ToClvm, FromClvm)]
#[clvm(list)]
pub struct MyState {
    pub field1: u64,
    #[clvm(rest)]
    pub field2: Bytes32,
}
```

## Architecture

```
action-layer-driver/
├── src/
│   ├── lib.rs              # Library entry point
│   ├── puzzle.rs           # PuzzleModule for loading/currying puzzles
│   ├── action_layer.rs     # ActionLayerConfig for merkle tree
│   ├── error.rs            # Error types
│   └── singleton/
│       ├── mod.rs          # Singleton module exports
│       ├── driver.rs       # SingletonDriver<S>
│       ├── types.rs        # Core types (LaunchResult, etc.)
│       ├── helpers.rs      # Standalone helper functions
│       └── spend_options.rs # SpendOptions for broadcasts
├── examples/
│   ├── singlelaunch/       # Two-action singleton demo
│   └── wallet/             # Wallet utilities
├── puzzles/
│   ├── src/                # Rue puzzle sources
│   └── output/             # Compiled puzzle hex
└── README.md
```

## Related

- [CHIP-0050](https://github.com/Chia-Network/chips/pull/140) - Action Layer specification
- [chia-wallet-sdk](https://github.com/Rigidity/chia-wallet-sdk) - Chia wallet SDK
- [Rue](https://github.com/Rigidity/rue) - Chia puzzle language

## License

MIT
