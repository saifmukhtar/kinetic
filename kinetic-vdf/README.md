# kinetic-vdf

## 1. Overview
`kinetic-vdf` is a pure Rust implementation of an RSA-based Verifiable Delay Function (VDF). It evaluates and verifies Wesolowski proofs of exponentiation over the RSA-2048 modulus, acting as the Sybil-resistance timing engine for the Kinetic network.

## 2. Usage & Integration
This crate implements the `VdfEngine` trait defined in `kinetic-core`. It is primarily consumed by `kinetic-daemon` and `kinetic-network` to artificially slow down network interactions (like mining names) and objectively verify the work of others. 

```rust
// Example integration pattern (pseudo-code)
use kinetic_vdf::RsaVdfEngine;
use kinetic_core::traits::VdfEngine;

let engine = RsaVdfEngine::new();
let proof = engine.evaluate(&challenge, iterations)?;
let is_valid = engine.verify(&challenge, &proof, iterations)?;
```

## 3. Internal Architecture
Under the hood, `kinetic-vdf` relies on repeated squarings over an unknown-factorization RSA group (the 1991 RSA-2048 challenge modulus).
*   **Evaluation:** Uses blockwise checkpointing to prevent out-of-memory errors on massive iteration counts.
*   **Fiat-Shamir Heuristic:** Uses `hash_to_prime` to deterministically derive the quotient prime `l` from the challenge and the result, removing the need for an interactive verifier.

## 4. Reading Guide
To fully understand this crate, we recommend reading it in the following order:

### Prerequisites
Before reading this crate, you must understand:
* **kinetic-core:** You must understand the `VdfEngine` trait, the `Commitment` and `VdfProof` payload structures, and the `VdfError` taxonomy.

### File Traversal (Leaf-First)
Do not read this crate top-to-bottom. Read it in this order:
1. `src/constants.rs` - The hardcoded RSA modulus.
2. `src/hash_to_prime.rs` - The cryptographic math used to bind the proof deterministically.
3. `src/lib.rs` - The `RsaVdfEngine` struct that stitches the math together into the `VdfEngine` trait implementation.

## 5. Taxonomy & Links
* **Taxonomy:** This crate belongs to Layer 6. Please read [`./LAYER_6.md`](./LAYER_6.md) to understand the strict architectural constraints of this layer.
* **Repository:** [https://github.com/saifmukhtar/kinetic](https://github.com/saifmukhtar/kinetic)
