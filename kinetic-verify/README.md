# kinetic-verify

## 1. Overview
`kinetic-verify` is a lightweight, `no_std`-compatible cryptographic verification library for the Kinetic network. It acts as the strict rules engine for validating state-mutating payloads, ensuring they possess mathematically valid Identity and Delegated signatures and Proof of Patience (VDF) claims before they are ever allowed to mutate node state.

## 2. Usage & Integration
This crate provides the `VerifySignature` trait, which extends Kinetic's core data models (like `NameEnvelope` and `Reveal`) with mathematically pure validation logic. Higher-level crates call this validation prior to accepting data from peers.

```rust
use kinetic_verify::signatures::VerifySignature;
use kinetic_types::name_record::NameEnvelope;

// Attempt to verify a payload received over the network
match record.verify_signature(&network_salt) {
    Ok(_) => println!("Signature is mathematically valid!"),
    Err(e) => eprintln!("Validation failed: {}", e.user_message()),
}
```

## 3. Internal Architecture
This crate does not implement cryptographic algorithms directly (that is handled by Layer 1 `kinetic-primitives`). Instead, it acts as the semantic bridge, enforcing how those strictly-typed taxonomy wrappers (like `IdentityPubKey` and `DelegatedPubKey`) are applied to Kinetic-specific data structures like identity delegations, manifest capability checks, and Name System mappings.

## 4. Reading Guide

### Prerequisites
Before reading this crate, you must understand:
* **`kinetic-primitives`**: You must understand how the strict key taxonomy wrappers function, avoiding raw bytes and raw keypairs.
* **`kinetic-types`**: You must be familiar with the `NameEnvelope` and `Reveal` data structures, as this crate exclusively operates on them.

### File Traversal (Leaf-First)
Do not read this crate top-to-bottom. Read it in this order:
1. `error.rs` - Understands the semantic boundary and the `SignatureVerifyError` taxonomy.
2. `signatures.rs` - The core logic implementing `VerifySignature` for data structures and managing delegated identity scope.
3. `lib.rs` - The overarching module exports and epoch constants.

## 5. Taxonomy & Links
* **Taxonomy:** This crate belongs to Layer 4. Please read [`./LAYER_4.md`](./LAYER_4.md) to understand the strict architectural constraints of this layer.
* **Repository:** [Kinetic Network](https://github.com/saifmukhtar/kinetic)
