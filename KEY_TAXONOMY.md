# Kinetic Key Taxonomy & Semantic Security Boundaries

## The Abstraction Problem
Because the Kinetic network standardizes heavily on `KineticKeypair` (ML-DSA-65) for nearly all domain operations, generic terms like "Sovereign Key" or "Public Key" are dangerously ambiguous. A key used for headless infrastructure routing has vastly different privileges than the key used to authorize a domain.

To prevent semantic drift, security vulnerabilities, and terminology confusion, this document defines the **strict naming conventions** for all keys in the Kinetic ecosystem. All documentation, variable names, and architectural discussions MUST use these exact terms.

---

## 1. Identity Key
* **Algorithm:** ML-DSA-65 (`KineticKeypair`)
* **Code Location:** `kinetic-local::identity`, `kid_manager.rs`
* **Role (Root of Trust):** The ultimate user authority. It is deterministically derived from the user's BIP39 mnemonic seed phrase. 
* **Capabilities:** 
  * Signs the outer `AuthorizedKid` envelope to bind an identity to a `.kin` name.
  * Signs `AuthorizedManifest` documents to grant permissions to Delegated Keys.
  * Direct signatures from this key strictly override and invalidate signatures from Delegated Keys on the DHT.
* **Lifecycle:** Permanent. Stored securely on the user's local disk (e.g., `identity.key`).

## 2. Controller Key
* **Algorithm:** ML-DSA-65 (`KineticKeypair`)
* **Code Location:** `kinetic-kid::document::Document::controller_keys`
* **Role (Identity Management):** The active keys embedded *inside* a Kinetic Identity Document (KID). 
* **Capabilities:** 
  * The SHA-256 hash of the *Primary* (first) Controller Key mathematically defines the DID string (`did:kin:<hash>`).
  * Authorized to sign *future updates* (key rotations) to the KID document.
* **Lifecycle:** Rotatable. If an active Controller Key is compromised, a new document can be issued rotating it out, provided the update is signed by a valid prior Controller Key.

## 3. Revoke Key
* **Algorithm:** ML-DSA-65 (`KineticKeypair`)
* **Code Location:** `kinetic-kid::document::Document::revocation_keys`
* **Role (Emergency Kill-Switch):** Highly secure "dark" keys embedded in the KID document.
* **Capabilities:** 
  * Strictly authorized to permanently deactivate (revoke) the KID document. 
  * **Cannot** be used to sign normal document updates, routing `Reveal` payloads, or capability manifests.
* **Lifecycle:** Permanent but strictly offline. Stored in cold storage.

## 4. Delegated Key
* **Algorithm:** ML-DSA-65 (`KineticKeypair`)
* **Code Location:** `kinetic-network::store::handlers`, `kinetic-daemon::api::heartbeat`
* **Role (Headless Infrastructure):** Operational keys used by background workers, cloud seeders (`kinetic-host`), or automated systems.
* **Capabilities:** 
  * Operates using an `AuthorizedManifest` (a capability proof signed by the Identity Key).
  * Continuously signs routine DHT payloads (like routing `Reveal` packets or PoW `Heartbeat`s) so the Identity Key doesn't have to remain exposed in server RAM.
* **Lifecycle:** Ephemeral / Rotatable. Can be easily discarded and replaced by issuing a new `AuthorizedManifest`.

## 5. Sovereign Key
* **Algorithm:** ML-DSA-65 (`KineticKeypair`)
* **Code Location:** `kinetic-types::action::NetworkAction`
* **Role (Global Governance):** The sovereign root keys hardcoded into the network genesis state.
* **Capabilities:** 
  * Authorizes global network state changes via `NetworkAction` payloads.
  * Required to map 1-character premium domains (`MapPrime`) and network infrastructure domains (`MapInfra`).
  * Can delegate authority via `RotateRootKey`.
* **Lifecycle:** Extremely restricted.

## 6. Epoch Key
* **Algorithm:** Ed25519 (`libp2p::identity::Keypair`)
* **Code Location:** `kinetic-network::pow::mine_p2p_keypair`, `kinetic-host::epoch`
* **Role (S/Kademlia Anti-Spam):** The standard Libp2p transport key used by standard users (`kinetic-daemon`) and headless seeders (`kinetic-host`) to satisfy the DHT Sybil-resistance difficulty requirement.
* **Capabilities:** 
  * Derives the node's ephemeral `PeerId` on the Kademlia DHT.
  * Establishes encrypted Noise/TLS TCP/QUIC connections between peers.
  * Holds absolutely zero authority over domain names or identity documents.
* **Lifecycle:** Highly ephemeral. Continuously ground via Proof-of-Work. The daemon and host dynamically *hot-swap* this identity and throw it away every time the network time epoch rotates.

## 7. Node Key
* **Algorithm:** Ed25519 (`libp2p::identity::Keypair`)
* **Code Location:** `kinetic-node::node_key`
* **Role (DHT Backbone):** The permanent identity used exclusively by `kinetic-node` cloud routers.
* **Capabilities:** 
  * Because these nodes act as the backbone bootstrap routers for the network, they **cannot** use Epoch Keys. They require a stable, unchanging `PeerId` so that new users can hardcode their Multiaddrs to join the network.
* **Lifecycle:** Permanent. Generated once and securely persisted to the cloud server's disk. It never rotates.

## 8. Host Key
* **Algorithm:** Ed25519 (`libp2p::identity::Keypair`)
* **Code Location:** `kinetic-host::host_key`
* **Role (Headless Seeder Dual-Identity):** The permanent connection identity used by `kinetic-host`.
* **Capabilities:** 
  * A `kinetic-host` utilizes a strict **Dual-Identity** system. It uses the *Epoch Key* (Type 6) to bypass DHT spam filters when inserting zone payloads, but uses the *Host Key* to provide a stable, permanent address for peers to request assets from it.
* **Lifecycle:** Permanent. Loaded from disk alongside the delegated capability manifest.

## 9. API Token
* **Algorithm:** 32-byte secure random entropy (CSPRNG), hex-encoded
* **Code Location:** `kinetic-daemon::api::auth`
* **Role (Local Daemon Security):** Standard HTTP Bearer tokens used to authorize local frontend applications (CLI, GUI wallets) to access the daemon's REST API.
* **Capabilities:** 
  * Strictly used for HTTP `Authorization: Bearer <token>` headers on localhost.
  * Completely unrelated to cryptographic proofs or P2P network authorization.
* **Lifecycle:** Ephemeral. Generated fresh and rotated every time `kinetic-daemon` boots, written to disk (e.g., `admin.token`, `nrs.token`).

---

## Appendix: DHT Logical Keys
*(Note: These are mathematical coordinates, not cryptographic asymmetric keypairs, but are included to disambiguate the word "key" in the codebase).*

* **Algorithm:** SHA-256 Hashes
* **Code Location:** `kinetic-types::name_record::{derive_storage_keys, derive_heartbeat_keys}`
* **Role:** 32-byte arrays used to mathematically map domain strings onto the physical Kademlia DHT address space (`H(salt || name || index)`).
