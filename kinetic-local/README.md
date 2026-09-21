# kinetic-local

## 1. Overview
`kinetic-local` provides OS and file system abstractions for the Kinetic network. It handles the secure persistence of identity keypairs, TOML configuration parsing, W3C DID document disk mapping, and OS process lifecycle signals.

## 2. Usage & Integration
This crate is orchestrated primarily by the executables (`kinetic-daemon`, `kinetic-node`, `kinetic-cli`) at startup to bootstrap the local node environment.

```rust
// Example integration pattern (pseudo-code)
use kinetic_local::config::load_config;
use kinetic_local::identity::load_keypair;
use kinetic_local::shutdown::wait_for_shutdown;

// 1. Boot up: Load the TOML configuration (or generate a default fail-closed one)
let config = load_config();

// 2. Load the master identity from the secure keystore
let keypair = load_keypair(&config.paths.keystore)?;

// 3. Keep the daemon alive until the OS sends SIGINT/SIGTERM
wait_for_shutdown().await;
```

## 3. Internal Architecture
Under the hood, `kinetic-local` enforces multiple local security boundaries:
*   **Fail-Closed Configuration:** Missing or malformed configurations will aggressively abort node startup rather than failing open with insecure defaults.
*   **Keystore Hardening:** Uses `secure_fs` to enforce POSIX `0600` file modes (on Unix) to prevent local privilege escalation and key theft by other users on the host machine.
*   **Action Sandboxing:** The `action.rs` module serializes network action states to disk, ensuring that action states survive node restarts without manual intervention.

## 4. Reading Guide
To fully understand this crate, we recommend reading it in the following order:

### Prerequisites
Before reading this crate, you must understand:
* **kinetic-core:** You must understand the underlying configuration structs (`KineticConfig`) and errors (`ConfigError`, `IdentityError`), as this crate operates heavily on them.
* **kinetic-kid:** You must understand how W3C documents (`Document`, `ControllerKey`) function, as the `kid_manager` module orchestrates their disk persistence.

### File Traversal (Leaf-First)
Do not read this crate top-to-bottom. Read it in this order:
1. `src/secure_fs.rs` - Start with the absolute lowest level file-permission enforcement.
2. `src/shutdown.rs` - The standalone process-lifecycle signal handlers.
3. `src/identity.rs` & `src/config.rs` - Discover how raw keys and configurations are read from disk.
4. `src/kid_manager.rs` - See how `.kin` network identities are created, mapped to Unix time, and serialized.
5. `src/lib.rs` - The module map.

## 5. Taxonomy & Links
* **Taxonomy:** This crate belongs to Layer 6. Please read [`./LAYER_6.md`](./LAYER_6.md) to understand the strict architectural constraints of this layer.
* **Repository:** [https://github.com/saifmukhtar/kinetic](https://github.com/saifmukhtar/kinetic)
