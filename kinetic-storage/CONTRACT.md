# Crate Contract: `kinetic-storage`

## 1. Domain Purpose
This is the **Persistence & Infrastructure** boundary (Layer 6). Its singular purpose is to provide a unified, cross-platform (Native + WASM), raw byte-level Key-Value store that implements the `kinetic_core::traits::StorageEngine` interface.

## 2. Pre-conditions (What the caller MUST do)
* **Serialization:** The caller MUST serialize their domain structs (e.g., `NameRecord`, `ActionState`) into raw `&[u8]` bytes before passing them to this crate. 
* **State Verification:** The caller MUST verify that the data being written is cryptographically sound and authorized. This crate blindly writes whatever bytes it is given.
* **Lock Handling:** The caller (the Daemon) MUST handle `DatabaseLocked` errors gracefully in case the user attempts to run two Daemons simultaneously against the same `~/.kinetic` folder.

## 3. Post-conditions & Guarantees (The "Always")
* **ACID Transactions:** Guarantees that (on native platforms via `redb`) all database writes are Atomic, Consistent, Isolated, and Durable. If the computer loses power mid-write, the database will not corrupt.
* **Concurrency Isolation:** Guarantees that readers are never blocked by writers.
* **WASM Safety:** Guarantees safe fallback mechanisms for browser environments (OPFS or memory limits) to prevent sandbox memory exhaustion attacks.

## 4. Anti-Guarantees (The "Never")
* **Zero Semantics/Serialization:** This crate NEVER parses JSON or Bincode. It does not know what a "Kinetic Identity" or "VDF Proof" is. It only understands keys and byte vectors.
* **Zero Consensus Logic:** This crate NEVER checks if an identity is expired or revoked before serving it from the database. It just returns the bytes.
* **Zero Transport:** This crate NEVER syncs state to other peers. That is the job of `kinetic-network`.

## 5. Trust Boundaries & Dependencies
* **Internal:** Fully trusts `kinetic-core` to provide the `StorageEngine` trait and error definitions.
* **External:** Fully trusts `redb` (on Native) and Web APIs (on WASM) to accurately enforce filesystem durability.
