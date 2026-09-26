# Crate Contract: `kinetic-primitives`

## 1. Domain Purpose
This is the absolute bedrock of the Kinetic Network (Layer 1). Its singular purpose is to execute pure, canonical cryptographic operations (hashing and ML-DSA-65 post-quantum signatures) and enforce the Kinetic Key Taxonomy via compile-time strict typing.

## 2. Pre-conditions (What the caller MUST do)
* **Entropy Management:** When generating a key from a seed (`from_seed`), the caller assumes 100% responsibility for ensuring the 32-byte seed contains true cryptographic entropy.
* **Payload Serialization:** Before calling `verify()`, the caller must deterministically serialize the message into bytes. This crate does not know how to serialize Kinetic structs.
* **Key Encryption:** When calling `to_secret_bytes()`, the caller receives a raw, unencrypted private key in memory. The caller MUST securely encrypt or wipe this byte array before persisting it. 
* **Authorization Checks:** The caller MUST verify that a given public key has the *authority* to perform an action. This crate only proves mathematical ownership.

## 3. Post-conditions & Guarantees (The "Always")
* **Taxonomy Isolation:** A developer can mathematically NEVER pass a `DelegatedPubKey` into a function that requires a `SovereignPubKey`. The Rust compiler will block it.
* **Canonical Hashing:** `sha256` and `sha256_concat` are guaranteed to output exactly 32 bytes without allocating unnecessary heap memory during chunked hashing.
* **Mathematical Integrity:** A successful `verify_signature` guarantees absolute mathematical proof that the holder of the private key signed the exact provided byte array.

## 4. Anti-Guarantees (The "Never")
* **Zero Semantics:** This crate NEVER knows what a `KID` (Identity), `NameRecord`, or `NetworkAction` is. It only understands `&[u8]`.
* **Zero Authorization:** This crate NEVER checks if a key is "active," "revoked," or "allowed" to sign something. It only verifies the math.
* **Zero State / I/O:** This crate NEVER touches the filesystem, the network, or the operating system. It has no concept of a "keychain" or "storage."

## 5. Trust Boundaries & Dependencies
* **Internal:** Depends on exactly 0 internal workspace crates.
* **External:** Fully trusts `ml-dsa` and `sha2` for mathematical correctness.
