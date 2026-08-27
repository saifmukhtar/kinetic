# kinetic-types

Core governance data structures and canonical serialization for the Kinetic network.

This crate is explicitly designed as a lightweight, zero-dependency `no_std`-compatible library (dependent only on `serde` and `ml-dsa`). It is used by both the main `kinetic-core` consensus engine and the air-gapped `kinetic-OS` offline key generator.

## Features
- **Post-Quantum Cryptography:** Fully integrated with `ml-dsa` (Dilithium3).
- **Canonical Serialization:** Provides `to_bytes()` for perfectly deterministic byte arrays used in signature verification.
- **Strict Parsing:** Includes robust validation and custom error types (`GovernanceTypeError`) for safe deserialization from raw byte slices.

## Usage

```rust
use kinetic_types::governance::GovernanceAction;

// Construct a governance proposal
let action = GovernanceAction::EmergencyHalt;

// Get the exact bytes required for an ML-DSA-65 signature
let payload = action.to_bytes();
```
