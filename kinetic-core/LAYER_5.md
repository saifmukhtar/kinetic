# Layer 5: The Core Engine

## 1. The Hook (Taxonomy)
This crate (`kinetic-core`) is the absolute nexus of the Kinetic workspace. It belongs to **Layer 5: The Core Engine**.

## 2. The Core Architectural Rule (The Invariant)
**This crate defines the rules of the network, but it never executes them.** 

`kinetic-core` provides the unified abstract traits (e.g., `StorageEngine`, `VdfEngine`, `KynProvider`), the global error taxonomy (`KineticError`), and the core wire-format types, but it explicitly **refuses to implement heavy infrastructure logic itself**. It knows *what* storage is, but it knows nothing about SQLite or Redb. It knows *what* network time is, but it does not implement the Libp2p streams required to fetch it.

## 3. The Horizontal Boundary
This crate exclusively owns the central abstractions and rules engine of the Kinetic network. It acts as the grand orchestrator and shared vocabulary.

* **It exclusively owns:** The protocol constants, the deterministic consensus math (difficulty scaling, fee pricing), the network configuration structures, the unified `What/Why/Fix` error taxonomy, and the abstract trait boundaries.
* **It explicitly ignores:** Concrete infrastructural implementations (database engines, physical networking, disk I/O, heavy cryptography). All of these are pushed up to Layer 6 and Layer 7 (`kinetic-storage`, `kinetic-vdf`, `kinetic-network`).

## 4. Why This Exists (Abstraction Defense)
By isolating the core definitions and traits in Layer 5, we achieve a perfectly decoupled architecture. If we need to swap out our underlying database engine from `redb` to `rocksdb`, or if we upgrade our P2P networking stack, `kinetic-core` remains untouched. 

It guarantees that all binaries (`kinetic-daemon`, `kinetic-node`, `kinetic-host`) share the exact same underlying rules, data models, and error behaviors without inadvertently inheriting heavy, unneeded infrastructural dependencies.
