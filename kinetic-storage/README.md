# Kinetic Storage

Concrete persistent storage implementations for the Kinetic Network.

## Architecture

This crate provides the core concrete implementation of the `StorageEngine` trait defined in `kinetic-core`. It utilizes a **dual-backend architecture** to dynamically adapt to its runtime environment:

### Native Execution (Linux/macOS/Windows)
When compiled for a native operating system, it leverages `redb`—a high-performance, embedded B-Tree database written in pure Rust.
- Maps keys and values to a persistent `kinetic_table`.
- Includes robust lockfile management and recovery mechanisms to gracefully handle abrupt daemon crashes.

### WebAssembly (Browser/WASM)
When compiled to `wasm32`, native filesystem I/O is unavailable. It seamlessly falls back to a fast, in-memory `RwLock<BTreeMap>`.
- Implements strict key-quota limits (e.g., maximum 10,000 keys) to prevent malicious network actors from causing browser tab Out-Of-Memory (OOM) crashes.
