# Kinetic Core

Core daemon primitives, VDF management, and network utilities for the Kinetic Network.

## Architecture

This crate acts as the central hub of logic for the Kinetic Network. It implements the primary types and interfaces required to run a full node, minus the actual TCP/IP networking, storage backends, and command-line execution frameworks.

**Key Components:**
- **Governance Logic:** Permissionless and Sovereign governance engines.
- **Drand Integration:** Verification of BLS12-381 G2 signatures from the League of Entropy.
- **VDF Management:** Core structs and verification logic (handed off to `kinetic-verify`) for chiavdf Proofs of Sequential Work.
- **Traits:** The foundational `StorageEngine`, `KynProvider`, and `GovernanceEngine` interfaces used to build modular frontends (like `kinetic-local` and `kinetic-network`).
