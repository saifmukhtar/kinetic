# kinetic-action

**Layer 2: Network Action and State Evolution**

`kinetic-action` is the core library responsible for managing the global configuration state of the Kinetic network. It tracks Sovereign keys, name mappings, and paused network timelines without interacting with the filesystem or asynchronous P2P network.

## Overview

In the Kinetic network, global state is not managed by a sprawling consensus mechanism, but rather through a highly constrained, single-signer Sovereign architecture (or an entirely immutable Permissionless architecture).

This crate provides the `ActionState` structure and the corresponding mathematical pure functions to:
1. Parse incoming `SignedActionMessage` payloads.
2. Hash and deduplicate actions to prevent replay attacks.
3. Validate Sovereign cryptographic signatures against the configured network root key.
4. Transition the network state (mapping infrastructure names, rotating keys, halting the network).

## Pluggable Engines

The crate implements a pluggable `ActionEngine` trait. Depending on the `network.json` configuration loaded by the daemon, the state transition logic routes to:

*   **`SovereignEngine`**: Relying entirely on offline Sovereign key signatures for state mutation. Used for private deployments or the earliest stages of network bootstrap.
*   **`PermissionlessEngine`**: A pure decentralized state where all privileged modifications are universally rejected.

## Usage

This crate operates exclusively on data structures. It is expected to be wrapped by higher-layer crates (like `kinetic-core` or `kinetic-daemon`) that handle disk persistence and GossipSub network broadcasting.

```rust
use kinetic_action::types::{ActionState, SignedActionMessage, ActionConfig};
use kinetic_action::logic::process_action_message;

// 1. Initialize state (normally loaded from disk by a higher layer)
let mut state = ActionState::new(current_kyn);

// 2. Process an incoming signed action
// match process_action_message(&mut state, &signed_msg, current_kyn, &config) { ... }
```

## Testing

This crate is rigorously tested to ensure deterministic state execution. All pure logic constraints are validated via doctests:

```bash
cargo test -p kinetic-action --doc
```

## Architecture

For more information on the strict abstraction boundaries and rules governing this crate, please read [LAYER_2.md](./LAYER_2.md).
