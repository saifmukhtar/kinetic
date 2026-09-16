# Layer 3: Network Data Shapes & Domain Binding

## 1. The Hook (Taxonomy)
The `kinetic-types` crate is part of **Layer 3: Network Data Shapes & Domain Binding**. It serves as the canonical schema and serialization hub for the entire Kinetic network.

## 2. The Core Architectural Rule (The Invariant)
**No external dependency or network logic.**
This layer is strictly data and schema definitions. It is forbidden from importing heavy network engines (like `libp2p`), consensus storage layers, or system-level hardware dependencies. It relies exclusively on native Rust primitives, Serde serialization, and Layer 1 cryptography (`kinetic-primitives`).

## 3. The Horizontal Boundary
This crate exclusively owns the **Network Wire Schemas**. It dictates exactly how data structures (such as KIDs, Name Records, IPC Proxies, and VDF Proofs) are serialized and deserialized across the network.
It explicitly ignores *how* that data is transmitted, *how* it is stored, and *how* consensus validates it. 

## 4. Why This Exists (Abstraction Defense)
Isolating serialization and data structures into a zero-networking hub allows clients (like browser extensions, lightweight hardware wallets, and detached toolchains) to parse and generate Kinetic network data perfectly without being forced to compile heavy P2P nodes or consensus storage engines. It guarantees that the wire format is universally deterministic across all clients.
