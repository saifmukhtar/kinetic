# kinetic-primitives

## 1. Overview
`kinetic-primitives` provides the absolute foundational cryptographic operations for the Kinetic network. It wraps the raw, underlying mathematical operations (like Post-Quantum signatures and hashing) into safe, domain-specific abstractions that are consumed by every higher-level crate in the workspace.

## 2. Usage & Integration
Higher-level crates use this crate to generate keypairs, sign payloads, verify signatures, and hash data without needing to know the specific underlying cryptographic implementations.

```rust
use kinetic_primitives::keys::KineticKeypair;
use kinetic_primitives::verify_mldsa;

// Generate a secure post-quantum keypair
let keypair = KineticKeypair::generate();
let public_key = keypair.pubkey_bytes();

// Sign an arbitrary payload
let message = b"hello kinetic";
let signature = keypair.sign(message);

// Verify the signature (returns Result<(), String>)
assert!(verify_mldsa(public_key, message, &signature).is_ok());
```

## 3. Internal Architecture
Under the hood, this crate currently implements:
* **Digital Signatures:** ML-DSA-65 (FIPS 204 Post-Quantum standard).
* **Hashing:** SHA-256.

## 4. Reading Guide
To fully understand this crate, we recommend reading it in the following order:

### Prerequisites
* None. As Layer 1, this crate is the absolute foundation and depends on no prior Kinetic domain knowledge.

### File Traversal (Leaf-First)
Do not read this crate top-to-bottom. Read it in this order:
1. `src/keys.rs` - Contains the `KineticKeypair` wrapper and serialization traits. Read this first to understand how the raw ML-DSA-65 engine is safely enclosed.
2. `src/lib.rs` - The root orchestrator that exports the unified cryptographic interface and hashing functions.

## 5. Taxonomy & Links
* **Taxonomy:** This crate belongs to Layer 1. Please read [`./LAYER_1.md`](./LAYER_1.md) to understand the strict architectural constraints of this layer.
* **Repository:** [Kinetic Network GitHub](https://github.com/saifmukhtar/kinetic)
