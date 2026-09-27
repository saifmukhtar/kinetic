# Layer 1: Network Time & Oracles

## 1. The Hook (Taxonomy)
This crate represents the Time Subsystem. It sits at **Layer 1: Network Time & Oracles** in the Kinetic 9-Layer Taxonomy, immediately above the absolute mathematical bedrock of Layer 0.

## 2. The Core Architectural Rule (The Invariant)
**This is the ONLY crate in the entire Kinetic workspace allowed to define or verify protocol time.** 
It strictly isolates raw Unix seconds (`UKyn`) from consensus network time (`Kyn`). It is purely mathematical—it performs **zero network I/O** to fetch the time beacon, and it never touches the local system OS clock to verify current state. All time payloads (like Drand beacons) must be fetched by the outer `kinetic-daemon` layer and injected into this crate for pure cryptographic evaluation.

## 3. The Horizontal Boundary
This crate exclusively owns **Time (The "When")**. 
It explicitly ignores everything else in the protocol. It knows absolutely nothing about identities (The "Who") or network actions (The "What"). It only answers questions like: *"Is this Drand time beacon mathematically valid?"* and *"Has this specific timestamp crossed the network's staleness threshold?"*

## 4. Why This Exists (Abstraction Defense)
In a decentralized network, relying on a local system clock is dangerous due to spoofing, drift, and sybil attacks. Time must be a mathematically proven consensus. Isolating Time into Layer 1 ensures that all higher layers (such as Layer 2 identities expiring or Layer 4 VDF proofs decaying) rely on a strictly monotonic, cryptographically proven external oracle (Drand) without needing to know *how* that oracle is verified.
