# kinetic-storage: Sled Storage Wrapper

The Kinetic protocol requires lightning-fast, persistent storage to maintain cryptographic proofs, configuration states, and active VDF reveals across reboots. `kinetic-storage` provides a robust wrapper around the `sled` embedded database.

## The Sled Database

`sled` is a high-performance, embedded, thread-safe database written entirely in Rust. It functions similarly to SQLite but is optimized for massive concurrent throughput, making it ideal for the asynchronous demands of the `kinetic-daemon`.

## Key Features & Auto-Recovery Logic

Because `sled` relies on memory-mapped files and aggressive caching, sudden power losses or hard crashes can occasionally lead to file corruption. `kinetic-storage` implements advanced wrapper logic to handle these catastrophic events gracefully.

### Auto-Recovery (`.corrupt.bak` Renaming)

When `kinetic-storage` attempts to initialize the `sled` database, it explicitly catches corruption errors. Instead of panicking and crashing the daemon permanently, it executes an auto-recovery protocol:

1.  **Detection**: It detects the specific `sled::Error` indicating database corruption.
2.  **Quarantine**: It renames the corrupted database directory by appending `.corrupt.bak` (e.g., `/tmp/kinetic_db.corrupt.bak`).
3.  **Reinitialization**: It creates a fresh, empty database directory in the original location and attempts to boot again.

This ensures that the Kinetic daemon can self-heal from unrecoverable storage corruption without requiring manual user intervention. While local un-published state may be lost in this scenario, the daemon will successfully restart, allowing it to re-sync with the DHT and resume operations.
