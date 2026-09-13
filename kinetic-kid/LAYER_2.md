# Layer 2: Domain Data (Identity Subsystem)

## 1. The Hook (Taxonomy)
This crate represents the Identity Subsystem. It sits at **Layer 2: Domain Data & Types** in the Kinetic 5-Layer Taxonomy.

## 2. The Core Architectural Rule (The Invariant)
**This crate is a Pure Mathematical Sandbox.** 
It performs zero network I/O, touches zero files on disk, and explicitly **does not access the local system OS clock**. All external states—such as verifying a document's expiration against the consensus network time (`Kyn`)—must be calculated and injected by the outer `kinetic-daemon` layer.

## 3. The Horizontal Boundary
This crate exclusively owns **Identity (The "Who")**. 
It explicitly ignores everything else in the protocol. It knows absolutely nothing about network routing, governance voting, RPC communication, or VDF blocks. It only answers one question: *"Is this identity document mathematically and structurally valid according to protocol bounds?"*

## 4. Why This Exists (Abstraction Defense)
This strict isolation allows any node on the Kinetic network (or even external web browsers) to perfectly and deterministically verify a Decentralized Identifier (DID) without needing to run a full blockchain node or connect to the P2P swarm.
