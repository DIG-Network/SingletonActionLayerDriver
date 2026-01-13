# Singleton Spawner Puzzle

A Rue puzzle for creating singletons that can spawn child singletons on the Chia blockchain.

## Overview

This puzzle serves as the inner puzzle for a singleton. When the singleton is spent, this puzzle:
1. **Always recreates the parent singleton** (maintains singleton continuity)
2. **Optionally spawns a child singleton** via a launcher

## Files

```
puzzles/
├── Rue.toml              # Rue project config
├── puzzles/
│   └── main.rue          # Singleton spawner inner puzzle
└── build/
    ├── singleton_spawner.clsp      # Compiled CLSP
    └── singleton_spawner.clvm.hex  # Serialized CLVM hex
```

## Puzzle Details

**Puzzle Hash (uncurried):** `bd994f0f45fe630d400d99403406455b101e4436f819cbcf91154f67849396e1`

### Curried Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `inner_puzzle_hash` | `Bytes32` | Hash of this puzzle (for recreating the singleton) |

### Solution

| Field | Type | Description |
|-------|------|-------------|
| `my_amount` | `Int` | Current coin amount (typically 1) |
| `spawn_config` | `SpawnConfig` | Spawn behavior configuration |
| `extra_conditions` | `List<Condition>` | Additional conditions (e.g., from owner/delegated puzzle) |

### SpawnConfig Struct

```rue
struct SpawnConfig {
    spawn_child: Bool,              // true to spawn, false to just recreate
    child_inner_puzzle_hash: Bytes32, // inner puzzle hash for child
    child_amount: Int,              // mojos for child launcher (must be odd)
}
```

## Output Conditions

### Without Spawn (`spawn_child = false`)
```
[CREATE_COIN inner_puzzle_hash my_amount, ...extra_conditions]
```

### With Spawn (`spawn_child = true`)
```
[
  CREATE_COIN LAUNCHER_PUZZLE_HASH child_amount,  // Child launcher
  CREATE_PUZZLE_ANNOUNCEMENT child_inner_hash,    // Bind to child
  CREATE_COIN inner_puzzle_hash my_amount,        // Recreate self
  ...extra_conditions
]
```

## Building

```bash
cd puzzles
rue build    # Compile puzzle
rue test     # Run tests
```

## Using in Rust

```rust
use hex_literal::hex;

// Compiled puzzle hex
const SINGLETON_SPAWNER_HEX: &[u8] = &hex!(
    "ff02ffff01ff02ffff03ff27ffff01ff04ffff04ffff0133ffff04ffff01a0eff07522495060c066f66f32acc2a77e3a3e737aca8baea4d1a64ea4cdc13da9ffff04ff81b7ff80808080ffff04ffff04ffff013effff04ff57ff808080ff028080ffff010280ff0180ffff04ffff04ffff04ffff0133ffff04ff02ffff04ff05ff80808080ff1780ff018080"
);

// To use: curry with inner_puzzle_hash, then wrap with singleton layer
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Singleton Coin                      │
│  ┌───────────────────────────────────────────────┐  │
│  │           Singleton Layer (outer)              │  │
│  │  - Enforces singleton rules (odd amount)       │  │
│  │  - Checks lineage proof                        │  │
│  │  ┌─────────────────────────────────────────┐  │  │
│  │  │    Singleton Spawner (inner puzzle)     │  │  │
│  │  │  - Recreates singleton                  │  │  │
│  │  │  - Optionally creates child launcher    │  │  │
│  │  └─────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## Spawn Flow

```
Parent Singleton ─[spend with spawn_child=true]─► Parent Singleton (recreated)
        │
        └──► Child Launcher (1 mojo) ─[spend]─► Child Singleton (new launcher_id)
```
