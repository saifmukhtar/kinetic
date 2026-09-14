# Layer 4: Infrastructure / Implementors

## 1. The Hook (Taxonomy)
This crate (`kinetic-local`) belongs to **Layer 4: Infrastructure**. It serves as the single abstraction boundary for all local OS interactions, file system operations, and keystore management.

## 2. The Core Architectural Rule (The Invariant)
**This crate must safely abstract the host operating system from the Kinetic daemon. The core consensus and logic crates must NEVER perform native disk I/O themselves.**

As an infrastructure module, `kinetic-local` owns the serialization and parsing of disk states (`config.toml`, identity keypairs, sovereign actions). It injects this configuration upward into the executing daemons.

## 3. The Horizontal Boundary
This crate explicitly owns local disk state. 
It explicitly ignores network topologies, P2P connections, or REST API routing. It does not speak to other nodes on the network; it only speaks to the hard drive and the local OS process (e.g., handling SIGINT/SIGTERM for graceful shutdowns).

## 4. Why This Exists (Abstraction Defense)
Isolating file system interactions in `kinetic-local` allows the core protocol crates (`kinetic-verify`, `kinetic-core`) to remain completely deterministic and pure. It also prevents security vulnerabilities by sandboxing all sensitive keypair disk operations behind strict OS-level permission checks (via `secure_fs`). 
