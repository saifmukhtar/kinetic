# Crate Contract: `kinetic-types`

## 1. Domain Purpose
This is the **Wire Protocol and Data Transfer Object (DTO)** layer (Layer 3). Its singular role is to define the exact structs, enums, and opcodes that traverse the P2P and HTTP networks, and provide canonical `serde` serialization (JSON/Bincode) for them.

## 2. Pre-conditions (What the caller MUST do)
* **Cryptographic Validation:** The caller MUST explicitly pipe these parsed structs into `kinetic-verify` to ensure they are mathematically sound. Successfully deserializing a struct from the network does NOT mean its signature is valid.
* **Network Context (Salt):** To generate `signable_bytes()`, the caller MUST provide the `network_salt` (Genesis block hash). This ensures signatures cannot be replayed across different Kinetic testnets/mainnets.

## 3. Post-conditions & Guarantees (The "Always")
* **Canonical Signing Layouts:** It mathematically guarantees the exact, deterministic byte-layout for how a struct is flattened before cryptographic signing (`signable_bytes()`), preventing cross-platform consensus splits.
* **Semantic Typestate:** It guarantees that fields are strictly typed (e.g., using `kinetic-kyn` types for time, and `kinetic-primitives` types for keys) rather than relying on raw `Vec<u8>` buffers, catching bad payloads at the `serde` layer before they hit the consensus engine.

## 4. Anti-Guarantees (The "Never")
* **Zero Cryptographic Verification:** This crate NEVER executes an ML-DSA-65 verification or SHA-256 validation. It simply stores the provided signature bytes in the struct.
* **Zero Consensus Logic:** This crate NEVER checks if a Name is expired, if a VDF proof is hard enough, or if an Action is authorized. It relies entirely on `kinetic-verify` to enforce network rules.
* **Zero State/Storage:** This crate NEVER reads or writes to the local database.

## 5. Trust Boundaries & Dependencies
* **Internal:** Fully trusts `kinetic-primitives`, `kinetic-kyn`, and `kinetic-kid` to provide the base cryptographic and identity types.
* **External:** Fully trusts `serde` and `bincode` for memory-safe binary packing and unpacking.
