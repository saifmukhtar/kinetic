# Layer 4: Infrastructure / Implementors

## 1. The Hook (Taxonomy)
This crate (`kinetic-storage`) belongs to **Layer 4: Infrastructure**. It is a concrete infrastructural implementor of abstract rules defined in Layer 3.

## 2. The Core Architectural Rule (The Invariant)
**This crate must depend on `kinetic-core` for its rules, but `kinetic-core` must NEVER depend on this crate.**

As an infrastructure module, `kinetic-storage` takes the abstract trait `StorageEngine` from `kinetic-core` and writes the actual disk I/O logic required to satisfy it using the `redb` embedded database.

## 3. The Horizontal Boundary
This crate exclusively owns byte-level disk persistence and filesystem locking.
It explicitly ignores network topologies, cryptographic verification, and state parsing. It does not know *what* data it is storing (it treats everything as raw `&[u8]`); it only knows *how* to safely write those bytes to disk without corruption.

## 4. Why This Exists (Abstraction Defense)
Isolating the heavy `redb` database engine (and WASM OPFS shims) in Layer 4 prevents the core logic from being contaminated by I/O dependencies. If the Kinetic network ever migrates to `rocksdb`, `lmdb`, or a cloud-native SQL backend, only this single Layer 4 crate needs to be rewritten or swapped out. The consensus math, core algorithms, and higher-level binaries remain completely untouched.
