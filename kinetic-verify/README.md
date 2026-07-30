# Kinetic Verify

Lightweight, `no_std`-compatible cryptographic verification library for the Kinetic Network.

This crate extracts the core verification logic out of the main `kinetic-core` daemon. It is specifically designed to be extremely lightweight, making it perfect for:
- Light clients (Mobile apps, Desktop wallets)
- Browser extensions (WASM targets)
- Systems that need to dynamically verify Kinetic data across multiple network forks.

## Features

- Verifies `ml-dsa-65` (Dilithium) post-quantum signatures for `.kin` domain reveals.
- Statically types `Reveal`, `Commitment`, `VdfProof`, and `PreviousProof` data structures.
- Generates dynamic, network-specific `signable_bytes` to prevent cross-network replay attacks.
- Zero heavy dependencies (No `tokio`, no `libp2p`, no `kademlia`).

## Usage

```rust
use kinetic_verify::Reveal;

// Receive a reveal object from an untrusted source
let reveal = Reveal { /* ... */ };

// Verify the signature is cryptographically valid for a specific network fork
let is_valid = reveal.verify_signature("kinetic-mainnet");

assert!(is_valid);
```
