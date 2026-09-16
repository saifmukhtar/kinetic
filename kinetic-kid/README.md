# kinetic-kid

## 1. Overview
`kinetic-kid` manages Kinetic Identity Documents (KIDs)—the self-sovereign identity layer for the Kinetic network. It establishes the W3C-compliant `did:kin` standard, defining how identities are created, signed, cryptographically verified, and extended with capability manifests.

## 2. Usage & Integration
This crate is used by higher-level networking and daemon layers to parse, validate, and authorize identities before granting access to network resources.

```rust
use kinetic_kid::{Document, Did, ControllerKey};

// Parse a W3C-compliant DID identifier
let did = Did::new("did:kin:0000000000000000000000000000000000000000000000000000000000000000").unwrap();

// Verifying a parsed Identity Document deterministically
// (Returns Ok(()) if JCS canonicalization and post-quantum signatures match)
assert!(document.verify().is_ok());
```

## 3. Internal Architecture
How this crate works under the hood:
* **W3C DID Compliance:** Follows the W3C DID Core specification, utilizing a dynamically configured `did:<nsp>:` namespace prefix (defaulting to `kin`).
* **JCS Canonicalization:** All documents are strictly formatted using the JSON Canonicalization Scheme (RFC 8785) prior to signing to prevent malleability attacks.
* **Hot vs Cold Keys:** Enforces a strict separation of privileges. `controller_keys` (Hot) are used for standard updates and manifests. `revocation_keys` (Cold) are cryptographically restricted to a single action: authorizing a `deactivated: true` payload to permanently burn the identity.

## 4. Reading Guide
To fully understand this crate, we recommend reading it in the following order:

### Prerequisites
Before reading this crate, you must understand:
* **`kinetic-primitives`:** You must understand how `KineticKeypair` and cryptographic signatures function as this crate relies entirely on them for verification.

### File Traversal (Leaf-First)
Do not read this crate top-to-bottom. Read it in this order:
1. `src/did.rs` - Start here to understand the strict W3C DID string validation constraints.
2. `src/bounded.rs` - Understand how the crate defends against JSON memory exhaustion attacks.
3. `src/document.rs` - The core struct. Learn how Hot/Cold keys and JCS verification operate.
4. `src/manifest.rs` - Learn how identities advertise external services with strict time-bounding.
5. `src/error.rs` - The semantic failure output of the entire sandbox.
6. `src/lib.rs` - The crate orchestrator and executable test suite.

## 5. Taxonomy & Links
* **Taxonomy:** This crate belongs to Layer 2. Please read [`./LAYER_2.md`](./LAYER_2.md) to understand the strict architectural constraints of this layer.
* **Repository:** [Kinetic Network GitHub](https://github.com/saifmukhtar/kinetic)
