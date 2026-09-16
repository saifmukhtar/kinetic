# Layer 1: Fundamental / Primitives

## 1. The Hook (Taxonomy)
This crate is the absolute foundation of the workspace. It sits at **Layer 1: Fundamental / Primitives** in the Kinetic 9-Layer Taxonomy.

## 2. The Core Architectural Rule (The Invariant)
**This is the ONLY crate in the entire Kinetic workspace allowed to know about specific cryptographic algorithms.** 
No other crate is permitted to import external cryptographic libraries or hardcode algorithm names (e.g., ML-DSA-65 or SHA-256). All other crates must consume the abstracted domain terminology (e.g., `KineticKeypair`, `verify_keypair`, and taxonomy wrappers like `IdentityPrivKey`) exposed exclusively by this crate.

## 3. The Horizontal Boundary
This crate exclusively owns **Pure Mathematics and Cryptography**. 
It explicitly ignores everything else. It knows absolutely nothing about identity documents, network routing, storage, state transitions, or P2P communication. It only answers questions like: *"Is this signature mathematically valid for these bytes?"*

## 4. Why This Exists (Abstraction Defense)
This strict isolation provides absolute **Abstraction Defense**. If the Kinetic protocol ever upgrades to a new post-quantum signature scheme in the future, isolating the cryptography into Layer 1 ensures that no other crate in the workspace needs to be rewritten. The rest of the network simply continues to call `KineticKeypair::generate()`, unaware of the underlying mathematical engine change.
