# kinetic-types

## 1. Overview
The `kinetic-types` crate serves as the canonical Layer 3 data schema hub for the Kinetic workspace. It provides the core data contracts, wire serialization formats, and cryptographic payload structures needed by nodes, clients, and proxies.

## 2. Usage & Integration
This crate is the backbone for any application or subsystem that needs to generate, parse, or verify Kinetic network data. 

```rust
// Example: Deterministically formatting a Domain Time payload
use kinetic_types::clock::Kyn;

let time = Kyn::new(150000);
let timestamp = time.to_utime();
```

## 3. Key Taxonomy & Signatures
Following the **Strict Key Taxonomy** pattern, `kinetic-types` NEVER relies on underlying algorithmic details (like ML-DSA). It strictly uses the abstracted wrappers from Layer 1 (`kinetic-primitives`):

- **`IdentityPubKey` / `IdentityPrivKey`**: Used for mapping domain names and verifying heartbeats.
- **`SovereignPubKey` / `SovereignPrivKey`**: Used for network-wide administrative actions and emergency halts.
- **Signatures**: Fields are explicitly named for the key that generated them (e.g., `identity_signature`, `owner_signature`, `sovereign_signatures`) rather than just `signature`.

## 4. Internal Architecture
`kinetic-types` defines multiple isolated domains:
- **Registration**: Proof of Patience proofs (`vdf.rs`) and Canonical Zones (`nrs.rs`).
- **P2P Networking**: Multiplexing payloads (`network.rs`, `cdn.rs`, `action.rs`).
- **Local IPC**: Zero-copy browser integration (`proxy.rs`).
- **Core Verification**: Cryptographic capability manifests and deterministic logging boundaries.

All structures implement strict Serde serialization to guarantee deterministic byte representation across the network.

## 5. Reading Guide
To fully understand this crate, we recommend reading it in the following Bottom-Up (Leaf-First) order:

### Prerequisites
Before reading this crate, you must understand:
* **kinetic-primitives:** You must understand how the `kinetic_keypair` taxonomy (Identity, Controller, Revoke, etc.) and basic hashing works.
* **kinetic-kid:** You must understand the formatting of a Kinetic Identity Document (KID).

### File Traversal (Leaf-First)
Do not read this crate top-to-bottom. It is a flat map of specialized payloads.
1. `error.rs` - The semantic output boundary and severity logger.
2. `clock.rs` - The foundation of Kinetic time (Kyn).
3. `identity.rs` - Cross-Network Replay Protection and Authorized Manifests.
4. `name_record.rs` - Name structures and heartbeat routing.
5. `nrs.rs` / `vdf.rs` - Registration schemas, DNS mapping, and mathematical proofs.
6. `network.rs` / `action.rs` / `cdn.rs` - P2P communication taxonomies.
7. `proxy.rs` - IPC proxy payloads.
8. `lib.rs` - The overarching schema hub.

## 6. Taxonomy & Links
* **Taxonomy:** This crate belongs to Layer 3. Please read [`./LAYER_3.md`](./LAYER_3.md) to understand the strict architectural constraints of this layer.
