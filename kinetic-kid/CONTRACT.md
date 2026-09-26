# Crate Contract: `kinetic-kid`

## 1. Domain Purpose
This crate implements the **Kinetic Identity Document (KID)** protocol (Layer 2). Its singular role is to parse, sanitize, and authorize identity state transitions (document updates and manifest claims) without ever touching a database or fetching the network time.

## 2. Pre-conditions (What the caller MUST do)
* **Provide State Context:** To verify an identity update, the caller MUST fetch the previous document from the DHT/Storage and pass it in as `previous_doc`. This crate cannot look up history.
* **Provide Time Context:** To verify if a manifest or document has expired, the caller MUST provide the `current_live_kyn`. This crate cannot fetch the time beacon.
* **Handle Network Transport:** The caller is responsible for fetching the JSON blobs over P2P or HTTP before feeding them into this crate's parsers.

## 3. Post-conditions & Guarantees (The "Always")
* **Memory Bounds Protection:** This crate guarantees immunity to JSON OOM (Out of Memory) attacks. A malicious document with 1,000,000 keys will instantly abort during parsing (enforced by `bounded.rs` at stream-time).
* **State Transition Authorization:** It mathematically guarantees that an update to an identity was signed by an authorized `Controller` key from the *previous* document state. 
* **Genesis Binding:** It guarantees that the DID string (`did:kin:abc...`) is an exact SHA-256 derivation of the primary controller public key (preventing identity theft).
* **Revocation Lockout:** It guarantees that a `deactivated: true` state can **only** be authorized by a cold-storage `revocation_key`, and never by a standard hot controller key.

## 4. Anti-Guarantees (The "Never")
* **Zero Storage/DHT Lookups:** This crate NEVER talks to the database, DHT, or local filesystem to verify if a DID exists. 
* **Zero Beacon Polling:** This crate NEVER communicates with Drand or the time oracle to verify expiration dates.
* **Zero Network Transport:** This crate NEVER makes an HTTP or P2P request. It operates strictly on raw bytes/JSON provided in memory.

## 5. Trust Boundaries & Dependencies
* **Internal:** Fully trusts `kinetic-primitives` (Layer 1) for the actual cryptographic signature math. Fully trusts `kinetic-kyn` (Layer 1.5) for the time structures.
* **External:** Fully trusts `serde` for JSON syntax parsing (though this crate restricts sequence limits).
