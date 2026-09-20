# Layer 4: Verification & Domain Rules

This document outlines the strict architectural boundaries and responsibilities of the `kinetic-action` crate within the Kinetic network.

## Architectural Layer

`kinetic-action` is firmly positioned at **Layer 4: Verification & Domain Rules**.

It is entirely responsible for tracking and transitioning the network's global configuration state over time, but it possesses **zero knowledge** of how that state is persisted to disk, transmitted over the peer-to-peer network, or received via the REST API.

## Core Responsibilities

1. **State Evolution (`ActionState`)**: Tracking active Sovereign keys and infrastructure protocol names.
2. **Timeline Management**: Tracking network pauses and calculating time-delay offsets (`paused_kyns_since`) caused by `EmergencyHalt` actions.
3. **Deterministic Verification**: Hashing network actions via SHA-256 and validating Sovereign cryptographic signatures before allowing state mutation.
4. **Pluggable Engines**: Implementing distinct verification rulesets (`SovereignEngine`, `PermissionlessEngine`) that can be swapped depending on the local `network.json` configuration.

## Strict Layer 4 Invariants

To maintain predictable, deterministic state transitions, this crate must adhere to the following rules:

- **No Asynchronous Execution**: `async/await`, `tokio`, or thread pools are strictly forbidden. State transitions must be instantaneous and mathematically pure.
- **No Disk I/O**: `std::fs` is forbidden. The active daemon or node process must handle loading the state from disk and passing the initialized `ActionState` struct into this crate.
- **No Network Networking**: `reqwest`, `libp2p`, and `hyper` are forbidden. This crate parses `SignedActionMessage` bytes but does not transmit them.
- **Dependency Isolation**: This crate may only depend on Layer 1 (`kinetic-primitives`), Layer 2 (`kinetic-kid`), and Layer 3 (`kinetic-types`). It must never depend on `kinetic-core`, `kinetic-network`, or `kinetic-rpc`.

## Abstraction Boundaries

All semantic failures within this crate are aggregated into the `ActionError` enum. 

This error implements a strict `severity()` mapping, allowing the upstream `kinetic-core` daemon to intelligently determine whether a failure (e.g., an unnormalized name) warrants an `Info` log, or if a failure (e.g., a corrupted Sovereign key) warrants a `Critical` panic.
