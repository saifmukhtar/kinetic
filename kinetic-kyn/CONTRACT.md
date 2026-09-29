# Crate Contract: `kinetic-kyn`

## 1. Domain Purpose
This crate manages the concept of **Time** in the Kinetic Network (Layer 1). Its singular role is to define strict types for network time (`Kyn`, `UKyn`) and cryptographically verify the external Drand time beacon (`RawKyn`). 

## 2. Pre-conditions (What the caller MUST do)
* **Network Transport:** The caller MUST fetch the beacon payload from the external internet (via HTTP or P2P). This crate has absolutely zero network dependencies.
* **Cache Management:** The caller MUST explicitly flag whether a `RawKyn` was fetched live or pulled from a database by setting `is_from_cache = true`. The crate uses this flag to enforce staleness rules, but it cannot verify the origin itself.
* **Environment Variables:** The caller (or the build environment) MUST provide the `BEACON_PUBLIC_KEY` and `KYN_PERIOD` constants at compile time.

## 3. Post-conditions & Guarantees (The "Always")
* **Time Type Isolation:** A developer can mathematically NEVER accidentally add Unix seconds (`UKyn`) directly to Network Time (`Kyn`). The Rust compiler will enforce explicit `.to_kyn()` conversions.
* **Beacon Integrity:** Calling `verify_beacon(false)` guarantees absolute cryptographic proof that the `RawKyn` was signed by the League of Entropy (BLS12-381 G2 signature) **AND** that the randomness string perfectly matches `SHA-256(signature)`.
* **State Evaluation:** `can_register()` and `can_heartbeat()` guarantee that the provided kyn satisfies the strict staleness and caching rules of the network protocol (e.g., rejecting cached kyns for VDF registrations).

## 4. Anti-Guarantees (The "Never")
* **Zero HTTP/Transport:** This crate NEVER fetches data. It does not know what `reqwest` or `libp2p` is.
* **Zero Disk I/O:** This crate NEVER caches the beacon to disk. It assumes the caller manages the local SQLite/Sled database.
* **Zero Semantic Payload:** This crate NEVER knows what a `KineticIdentity` or `NetworkAction` is. It only understands pure time and beacon math.

## 5. Trust Boundaries & Dependencies
* **Internal:** Fully trusts `kinetic-primitives` (Layer 0) for SHA-256 hashing.
* **External:** Fully trusts `beacon-verify` and `hex` for BLS12-381 G2 signature validation against the hardcoded public key.
