# Crate Contract: `kinetic-verify`

## 1. Domain Purpose
This is the **Stateless Consensus & Authorization** layer (Layer 4). Its singular role is to execute pure, `no_std`-compatible validation of network payloads, ensuring that complex domain rules (like delegated capabilities and scope containment) are cryptographically enforced before a payload enters the state machine.

## 2. Pre-conditions (What the caller MUST do)
* **Global State Verification:** The caller (the Daemon or Storage engine) MUST verify that the Identity used in the payload hasn't been revoked in the global DHT. This crate only verifies the *local* mathematical consistency of the embedded manifest and identity document.
* **Temporal Validation:** The caller MUST verify that the payload hasn't expired (e.g., checking if the `kyn` is too old). This crate only verifies signatures, not time bounds.
* **Network Context:** The caller MUST provide the exact `network_salt` (Genesis block hash) to prevent cross-network replay attacks.

## 3. Post-conditions & Guarantees (The "Always")
* **Delegated Scope Containment:** Guarantees that an ephemeral/headless key can mathematically *never* act outside the specific `.kin` name and exact capabilities (e.g., `kinetic.capability.dns_update`) explicitly granted by the root identity.
* **Cryptographic Finality:** Guarantees that if `verify_signature()` returns `Ok(())`, the payload mathematically matches the public key, the root owner authorized the capability, and the network salt aligns.

## 4. Anti-Guarantees (The "Never")
* **Zero Global State/DHT:** This crate NEVER talks to the network or the database. It does not know if a newer Identity Document exists in the DHT that revokes the current one.
* **Zero Network Transport:** This crate NEVER makes an HTTP or P2P request.
* **Zero Temporal Awareness:** This crate NEVER queries the Drand beacon to verify the freshness of the payload.

## 5. Trust Boundaries & Dependencies
* **Internal:** Fully trusts `kinetic-types` for canonical byte layouts (`signable_bytes`), and `kinetic-primitives` / `kinetic-kid` for the underlying math and identity structures.
* **External:** Operates entirely in a pure, offline mathematical sandbox.
