# kinetic-core

## 1. Overview
`kinetic-core` is the foundational shared kernel for the Kinetic decentralized naming network. It provides the core data models, protocol constants, cryptographic state machines, error hierarchies, and common interfaces used across all Kinetic binaries (`kinetic-daemon`, `kinetic-node`, `kinetic-host`).

## 2. Usage & Integration
This crate serves as the shared vocabulary for the entire workspace. Whenever you need to handle network configurations, parse core domain errors, leverage protocol constants, or implement an infrastructure trait (like a new storage engine), you interface with `kinetic-core`.

By depending on `kinetic-core`, higher-level binaries are guaranteed to enforce the exact same network rules and consensus math without needing to implement the heavy Layer 6 infrastructure directly.

## 3. Internal Architecture
`kinetic-core` relies on a highly decoupled architecture utilizing strict trait boundaries:
*   **Unified Taxonomy:** A single, meticulously categorized error module (`kinetic_core::error`) using the `What/Why/Fix` paradigm and severity signaling.
*   **Core Traits:** Abstract interfaces for Verifiable Delay Functions (`VdfEngine`), network time providers (`KynProvider`), and persistent storage (`StorageEngine`).
*   **Deterministic Math:** Isolated pure-math routines for difficulty scaling and name-length pricing to ensure cross-platform consistency in consensus.
*   **Security Primitives:** Deeply integrated SSRF defenses and IP classification for P2P and RPC networking boundaries.

## 4. Reading Guide
To fully understand this crate, we recommend reading it in the following order:

### Prerequisites
Before reading this crate, you must understand:
* **kinetic-types:** You must be familiar with the foundational network payloads (`NrsEntry`, `Commitment`, `VdfProof`) and the Network Actions which form the raw data operated on by this core kernel.

### File Traversal (Leaf-First)
Do not read this crate top-to-bottom. Read it in this order:
1. `src/constants.rs` - Contains the global protocol constants that drive everything.
2. `src/error.rs` - Establishes the unified error taxonomy and severity classifications.
3. `src/traits.rs` - Defines the strict Layer 5 boundaries (`StorageEngine`, `VdfEngine`, `KynProvider`) that Layer 6 must implement.
4. `src/consensus_math.rs` - The pure deterministic math driving network pricing and VDF targets.
5. `src/drand.rs` & `src/action.rs` - The internal logic adapters for handling abstract concepts like network time and network actions.
6. `src/config.rs` - The daemon and node configuration structures.
7. `src/lib.rs` - The final module layout and exported orchestration layer.

## 5. Taxonomy & Links
* **Taxonomy:** This crate belongs to Layer 5. Please read [`./LAYER_5.md`](./LAYER_5.md) to understand the strict architectural constraints of this layer.
* **Repository:** [https://github.com/saifmukhtar/kinetic](https://github.com/saifmukhtar/kinetic)
