# kinetic-storage

## 1. Overview
`kinetic-storage` provides persistent, high-performance key-value storage for the Kinetic network. It seamlessly bridges native and browser environments by acting as a wrapper over `redb` (a pure-Rust embedded database) on desktop/server, and an OPFS-backed `BTreeMap` on WASM platforms.

## 2. Usage & Integration
This crate implements the `StorageEngine` trait defined in `kinetic-core`. It is injected into the `kinetic-daemon` and `kinetic-network` layers to handle all durable state persistence, such as the DHT record cache and sovereign action logs.

```rust
// Example integration pattern (pseudo-code)
use kinetic_storage::KineticStorage;
use kinetic_core::traits::StorageEngine;

// The storage engine automatically handles locking and directory creation
let storage = KineticStorage::new("/var/lib/kinetic/db")?;

// Write raw bytes
storage.put(b"prefix:key1", b"payload_data")?;

// Retrieve and scan
let value = storage.get(b"prefix:key1")?;
let results = storage.scan_prefix(b"prefix:", Some(10))?;
```

## 3. Internal Architecture
Under the hood, `kinetic-storage` handles critical infrastructural guarantees:
*   **Native (`redb`):** Uses strict ACID transactions and OS-level file locking. It prevents multiple `kinetic-daemon` instances from corrupting the same database file simultaneously (`StorageError::DatabaseLocked`).
*   **WASM (OPFS):** Implements a bespoke `BTreeMap` backed by the Origin Private File System (`FileSystemSyncAccessHandle`) to provide synchronous, durable storage in browser contexts without requiring asynchronous bridging.
*   **Quota Enforcement:** Defends against memory exhaustion in fallback WASM environments by enforcing a hard 10,000-key limit when OPFS is unavailable.

## 4. Reading Guide
To fully understand this crate, we recommend reading it in the following order:

### Prerequisites
Before reading this crate, you must understand:
* **kinetic-core:** You must understand the `StorageEngine` trait and the `StorageError` taxonomy, as this crate's sole purpose is to implement those boundaries.

### File Traversal (Leaf-First)
Because this crate relies heavily on conditional compilation for cross-platform support, all logic is centralized in a single file, split by `cfg` attributes.
1. `src/lib.rs (mod native)` - Read the `redb` implementation first, as it defines the primary production behavior for desktop/server nodes.
2. `src/lib.rs (mod wasm)` - Read the WASM implementation second to see how OPFS filesystem handles are managed synchronously in the browser.

## 5. Taxonomy & Links
* **Taxonomy:** This crate belongs to Layer 6. Please read [`./LAYER_6.md`](./LAYER_6.md) to understand the strict architectural constraints of this layer.
* **Repository:** [https://github.com/saifmukhtar/kinetic](https://github.com/saifmukhtar/kinetic)
