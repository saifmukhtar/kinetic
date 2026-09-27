# Crate Contract: `kinetic-local`

## 1. Domain Purpose
This is the **OS & Disk Orchestration** boundary (Layer 6). Its singular purpose is to abstract the physical computer away from the consensus engine. It handles filesystem I/O, local keystore management, TOML configuration loading, and POSIX signal handling (graceful shutdown).

## 2. Pre-conditions (What the caller MUST do)
* **OS File Permissions:** The caller (usually the Daemon or CLI binary) MUST be executed by an OS user with read/write permissions to the `~/.kinetic` (or `$KINETIC_PATH`) directory.
* **Handle Process Exits:** The caller MUST be prepared for the process to be hard-aborted. If the configuration file is structurally malformed, this crate will intentionally call `std::process::exit(1)` rather than returning a soft error.

## 3. Post-conditions & Guarantees (The "Always")
* **Atomic Cryptographic Persistence:** Guarantees that private key material is written to disk using atomic `.tmp` file swaps. A node crash or power loss during a key generation will *never* result in a corrupted or partially written keyfile.
* **Keystore Sandboxing:** Guarantees that written secrets use POSIX `0o600` (`rw-------`) permissions (on Unix systems), preventing other local OS users from reading the keystore.
* **Fail-Closed Configuration:** Guarantees that the node will refuse to boot rather than silently falling back to insecure defaults if the config is malformed.

## 4. Anti-Guarantees (The "Never")
* **Zero Networking/DHT:** This crate NEVER talks to the global network. When `load_local_kid()` is called, it only reads from the local hard drive. It has no idea what the global state of the network is.
* **Zero Consensus Logic:** This crate NEVER mathematically verifies a payload against the network rules. It merely reads bytes from disk and hands them to the lower layers.

## 5. Trust Boundaries & Dependencies
* **Internal:** Fully trusts `kinetic-core` for configuration schemas and `kinetic-kid` / `kinetic-primitives` for the actual cryptography structures.
* **External:** Fully trusts the underlying Operating System (Linux/macOS/Windows) to accurately enforce filesystem permissions and atomic renames.
