# Kinetic — Cryptography Notes
 
A reference for reviewers: every cryptographic primitive Kinetic uses, *why* it
is used, how it is applied, and the invariants that must hold. If you are a
cryptographer looking at Kinetic, this is the fastest way to find the parts worth
your scrutiny.
 
---
 
## 1. Primitives at a glance
 
| Primitive | Library | Used for |
|-----------|---------|----------|
| **ML-DSA-65** | `ml-dsa` | Post-quantum identity keys, name-ownership signatures, governance signatures, KID/manifest signatures (NIST FIPS 204 Level 3) `(Source: kinetic-core/src/types/)` |
| **Ed25519** | `ed25519-dalek` | Ephemeral P2P node identities and Noise transport handshake `(Source: libp2p)` |
| **SHA-256** | `sha2` | DID derivation, action hashing, commit hashes, randomness binding `(Source: kinetic-core/src/types/)` |
| **BLS (drand)** | drand Quicknet (verify pinned public key) | Verifying the external randomness beacon `(Source: kinetic-core/src/drand.rs)` |
| **VDF** | Chia VDF / `kyn-vdf` (`kinetic-verify`) | Proof-of-time cost for registration/renewal (C++ FFI & pure Rust Class Group arithmetic) |
| **CSPRNG** | `getrandom` / `OsRng` | All key and entropy generation |
| **BIP-39** | `bip39` | 24-word mnemonic seed for node identity backup |
| **JCS** | JSON Canonicalization Scheme | Deterministic serialization of KID docs/manifests before signing `(Source: kinetic-kid/src/)` |
| **PBKDF2 + zeroize** | `pbkdf2` + `zeroize` | Encrypting keypairs at rest (600,000 wallet iterations, 2,048 keygen); wiping secrets from memory |

---

## 2. Post-Quantum Identity Keys (ML-DSA-65)

- Kinetic exclusively uses **ML-DSA-65** (Module-Lattice-Based Digital Signature Algorithm, NIST FIPS 204) for all identity, name ownership, and governance keys.
- Generated with `OsRng` / `getrandom` — never a seeded or predictable RNG.
- Public keys are 1,952 bytes; signatures are 3,309 bytes.
- The seed workflow derives the node identity from a **BIP-39 24-word mnemonic**;
  the mnemonic is shown once and never recoverable, and the derived keypair is
  written with `0o600` permissions via a temp-file + atomic-rename helper.
- **Invariant:** private key material is written only with `0o600`, is never
  logged, and is zeroized where held in memory. Infrastructure identity files
  (`kinetic-node`, `kinetic-host`, sim keygen) must use the same `0o600` helper —
  do not fall back to `std::fs::write` with default permissions.

---

## 3. DID Derivation & KID Verification (ML-DSA-65)

- `did:kin:<hex>` where `hex = sha256(primary_controller_mldsa65_pubkey)` (lowercase,
  64 hex chars, strictly validated).
- **Verification** (`kinetic-kid`):
  - **Genesis Publication (`verify_genesis()`):** Enforces that the `did:kin:<hex>` identifier matches `hex(sha256(primary_controller_key_bytes))`.
  - **Stateless Document Verification (`verify()`):** Checks that the document is internally consistent, canonicalized via JCS, and signed by an active controller key listed in the document.
  - **Key Rotation Updates (`is_authorized_update()`):** Verifies that an incoming document update is signed by a valid controller key from the *previously* stored document, enabling secure key rotation while locking the DID root.
- Signatures are over the **JCS-canonical** document with the `signature` field
  omitted, so signing is deterministic and canonicalization-independent.
- Controller key count is bounded (≤ 20) and revocation keys count is bounded (≤ 20).
- **Invariants to keep:** (a) manifests must be bound to their KID *and* verified
  against a controller key (not just the name-owner key); (b) manifest `version`
  must be monotonic and `valid_from` enforced to prevent rollback; (c) if
  `deactivated: true` is set, the document must be signed by one of the authorized `revocation_keys`.

---

## 4. Ephemeral Transport Identities (Ed25519)

- Ephemeral Ed25519 keys are used strictly at the `libp2p` networking layer for Noise transport handshakes and Kademlia routing.
- This isolates the underlying ML-DSA-65 post-quantum user identity: even if an attacker compromises a transient node's Ed25519 PeerID, they can **never** hijack `.kin` names or forge KID capability signatures.

---

## 5. Name Ownership: Commit / Reveal + VDF

- **Commit/reveal** prevents front-running: a hash commitment is published first,
  so an observer cannot steal the plaintext name before the reveal.
- **VDF (proof-of-time)** is the *cost*: the registrant must run a sequential
  computation whose challenge is derived from drand randomness. This replaces a
  registrar/token fee with wall-clock compute that cannot be parallelized away.
- **Invariants:** (a) the VDF challenge must be bound to the correct drand kyn
  and to the name/key (no reuse across names); (b) proof size is bounded before
  verification; (c) verification runs **off** the async reactor
  (`spawn_blocking` + bounded concurrency) so a flood of proofs cannot starve the
  node; (d) records are signature- and VDF-verified **before** being accepted into
  the DHT store — never trust-on-deserialize.

---

## 6. Randomness Beacon (drand Quicknet)

- Kinetic pins the Quicknet chain (public key + chain hash in `network.json`) and
  fetches pulses over HTTPS from multiple providers.
- **Critical invariant — randomness must be bound to the signature.** Verifying
  the BLS signature over the kyn is necessary but **not sufficient**: the
  resolver must also verify that the delivered `randomness` equals the beacon's
  defined derivation from the signature (for Quicknet, `randomness = SHA-256(sig)` `Source: kinetic-core/src/drand.rs:120-126`).
  Otherwise a MITM/malicious endpoint could supply a valid signature alongside
  attacker-chosen randomness, steering every VDF challenge.
- **Endpoint authenticity:** only fetch over HTTPS; never accept beacon endpoints
  injected via plaintext DNS TXT without an allow-list / pinning. `kinetic-forge`
  must not offer plaintext `http://` beacon endpoints for real deployments.
- **Availability:** drand is a documented external dependency (see
  `THREAT_MODEL.md` §7). Multiple providers reduce, but do not eliminate, this.

---

## 7. Governance Signatures (ML-DSA-65)

- Actions are serialized to **canonical, domain-separated bytes**
  (`SignedGovernanceMessage::to_bytes`): a 1-byte action tag followed by
  length-prefixed fields, then `timestamp_kyn`.
- Signatures are post-quantum **ML-DSA-65** by the Sovereign Root Key.
- **Invariants:** (a) Emergency actions (`EmergencyHalt` / `EmergencyResume`) and key rotations (`RotateRootKey`) execute immediately upon Root key verification; (b) the production ML-DSA-65 root key is pinned and tested via SHA-256 fingerprint in `prod_keys::ROOT_PUBLIC_KEY_HEX`.

---

## 8. Canonicalization (JCS)

- KID documents and manifests are signed over their **JCS** form with the
  signature field omitted. JCS gives a single deterministic byte string for a
  given JSON value, so signers/verifiers on different platforms agree.
- **Invariant:** never sign or verify over a non-canonical serialization
  (e.g. `serde_json::to_string` without canonicalization) for these objects.

---

## 9. Storage at Rest

- Keypairs encrypted with **PBKDF2**-derived keys; secrets **zeroized** after use.
- Sled KV store on native. **Invariant:** distinguish the *record cache* (safe to
  reset on corruption) from *authoritative local state* (ownership/identity — must
  fail closed on corruption, never silently reset to empty). Governance state must
  not silently reset to uninitialized mode on a corrupt file.

---

## 10. Things Reviewers Should Specifically Try to Break

1. Feed a valid drand signature with mismatched `randomness` — is it rejected?
2. Submit a Reveal whose VDF challenge is derived from a *different* kyn/name —
   accepted?
3. Flood inbound `PutRecord` / connections — does verification stay off the
   reactor and bounded?
4. Publish a genesis KID whose controller pubkey does **not** hash to the DID — rejected?
5. Replay an old, lower-`version` manifest — rejected?
6. Trigger an unauthorized emergency action without the valid ML-DSA-65 Root Key — rejected?
7. Corrupt/truncate the governance or ownership state file — does it fail closed?
8. Path-traversal / SSRF / DNS-rebinding against the proxy and DNS resolver.
9. Ask a wasm/mobile light client to resolve a name backed only by colluding peers
   with no valid VDF — is it accepted?

(These map directly to the findings in the audit reports.)
