# kinetic-kyn

## 1. Overview
`kinetic-kyn` manages the concept of **Time** in the Kinetic Network. It defines strict types for network time and cryptographically verifies the external Drand time beacon, providing a monotonic, verifiable clock that the rest of the network relies upon.

## 2. Usage & Integration
Higher-level crates use this crate to ensure timestamps are mathematically sound and to verify the current network time before mutating state (like renewing a domain or signing an action).

Crucially, higher-level crates should use the semantic wrappers (e.g., `Kyn`, `UKyn`) to ensure strict compile-time boundaries between raw Unix seconds and consensus-verified Network Time.

```rust
use kinetic_kyn::types::{Kyn, UKyn, GenesisKyn};
use kinetic_kyn::beacon::{verify_beacon, RawKyn};

// Convert raw Unix time to Network Time (Kyn)
let genesis = GenesisKyn::from(1600000000);
let current_kyn = Kyn::new(150);

// Verify an incoming Drand beacon payload
let raw_beacon = RawKyn {
    round: 150,
    signature: vec![/* BLS12-381 G2 bytes */],
    previous_signature: vec![/* bytes */],
};

// Returns mathematically proven time if the signature matches the League of Entropy
assert!(verify_beacon(&raw_beacon, false).is_ok());
```

## 3. Internal Architecture
Under the hood, this crate implements:
* **Time Taxonomy:** Strict Newtype pattern wrappers (`Kyn`, `UKyn`, `GenesisKyn`).
* **Oracle Verification:** BLS12-381 G2 signature verification of the League of Entropy (Drand) beacon.
* **Temporal Math:** Safe deltas, duration conversions, and overflow-protected time boundaries.

## 4. Reading Guide
To fully understand this crate, we recommend reading it in the following order:

### Prerequisites
* **`kinetic-primitives` (Layer 0):** This crate relies on the foundational SHA-256 hashing provided by Layer 0 to hash the beacon signatures.

### File Traversal (Leaf-First)
Do not read this crate top-to-bottom. Read it in this order:
1. `src/types.rs` - Contains the `Kyn` and `UKyn` wrappers. Read this first to understand the vocabulary of Kinetic Time.
2. `src/math.rs` - Contains the logic for calculating time deltas safely.
3. `src/beacon.rs` - Contains the cryptographic verification logic for the Drand oracle.
4. `src/lib.rs` - The root orchestrator that exports the unified Time interface.

## 5. Taxonomy & Links
* **Taxonomy:** This crate belongs to Layer 1. Please read [`./LAYER_1.md`](./LAYER_1.md) to understand the strict architectural constraints of this layer.
* **Repository:** [Kinetic Network GitHub](https://github.com/saifmukhtar/kinetic)
