# Kinetic — Cryptography Notes
 
A reference for reviewers: every cryptographic primitive Kinetic uses, *why* it
is used, how it is applied, and the invariants that must hold. If you are a
cryptographer looking at Kinetic, this is the fastest way to find the parts worth
your scrutiny.
 
---
 
## 1. Primitives at a glance
 
| Primitive | Library | Used for |
|-----------|---------|----------|
| **Ed25519** | `ed25519-dalek` | All identity keys, name-ownership signatures, governance signatures, KID/manifest signatures |
| **SHA-256** | `sha2` | DID derivation, action hashing, commit hashes, randomness binding |
| **BLS (drand)** | drand Quicknet (verify pinned public key) | Verifying the external randomness beacon |
| **VDF** | Chia VDF (C++ via FFI in `kinetic-vdf`) | Proof-of-time cost for registration/renewal |
| **CSPRNG** | `getrandom` / `OsRng` | All key and entropy generation |
| **BIP-39** | `bip39` | 24-word mnemonic seed for node identity backup |
| **JCS** | JSON Canonicalization Scheme | Deterministic serialization of KID docs/manifests before signing |
| **PBKDF2 + zeroize** | — | Encrypting keypairs at rest; wiping secrets from memory |
 
---
 
## 2. Identity keys (Ed25519)
 
- Generated with `OsRng` / `getrandom` — never a seeded or predictable RNG.
- The seed workflow derives the node identity from a **BIP-39 24-word mnemonic**;
  the mnemonic is shown once and never recoverable, and the derived keypair is
  written with `0o600` permissions via a temp-file + atomic-rename helper.
- **Invariant:** private key material is written only with `0o600`, is never
  logged, and is zeroized where held in memory. Infrastructure identity files
  (`kinetic-node`, `kinetic-host`, sim keygen) must use the same `0o600` helper —
  do not fall back to `std::fs::write` with default permissions.
 
---
 
## 3. DID derivation & KID verification
 
- `did:kin:<hex>` where `hex = sha256(controller_ed25519_pubkey)` (lowercase,
  64 hex chars, strictly validated).
- **Verification** (`kinetic-kid`): for a signed KID document, the verifier
  recomputes `sha256(pubkey)` for each controller key and requires it to equal the
  DID's method-specific id *before* accepting a signature. This means **only the
  holder of the private key whose public key hashes to the DID can control it** —
  the classic DID-hijack (swapping in an attacker's controller key) is blocked.
- Signatures are over the **JCS-canonical** document with the `signature` field
  omitted, so signing is deterministic and canonicalization-independent.
- Controller key count is bounded (≤ 20).
- **Invariants to keep:** (a) manifests must be bound to their KID *and* verified
  against a controller key (not just the domain-owner key); (b) manifest `version`
  must be monotonic and `valid_from` enforced to prevent rollback; (c) if
  `revocation_keys` are a feature, they must actually be enforced during verify.
 
---
 
## 4. Name ownership: commit / reveal + VDF
 
- **Commit/reveal** prevents front-running: a hash commitment is published first,
  so an observer cannot steal the plaintext name before the reveal.
- **VDF (proof-of-time)** is the *cost*: the registrant must run a sequential
  computation whose challenge is derived from drand randomness. This replaces a
  registrar/token fee with wall-clock compute that cannot be parallelized away.
- **Invariants:** (a) the VDF challenge must be bound to the correct drand round
  and to the name/key (no reuse across names); (b) proof size is bounded before
  verification; (c) verification runs **off** the async reactor
  (`spawn_blocking` + bounded concurrency) so a flood of proofs cannot starve the
  node; (d) records are signature- and VDF-verified **before** being accepted into
  the DHT store — never trust-on-deserialize.
 
---
 
## 5. Randomness beacon (drand Quicknet)
 
- Kinetic pins the Quicknet chain (public key + chain hash in `network.json`) and
  fetches pulses over HTTPS from multiple providers.
- **Critical invariant — randomness must be bound to the signature.** Verifying
  the BLS signature over the round is necessary but **not sufficient**: the
  resolver must also verify that the delivered `randomness` equals the beacon's
  defined derivation from the signature (for Quicknet, `randomness = SHA-256(sig)`).
  Otherwise a MITM/malicious endpoint could supply a valid signature alongside
  attacker-chosen randomness, steering every VDF challenge.
- **Endpoint authenticity:** only fetch over HTTPS; never accept beacon endpoints
  injected via plaintext DNS TXT without an allow-list / pinning. `kinetic-forge`
  must not offer plaintext `http://` beacon endpoints for real deployments.
- **Availability:** drand is a documented external dependency (see
  `THREAT_MODEL.md` §7). Multiple providers reduce, but do not eliminate, this.
 
---
 
## 6. Governance signatures
 
- Actions are serialized to **canonical, domain-separated bytes**
  (`SignedGovernanceMessage::to_canonical_bytes`): a 1-byte action tag followed by
  length-prefixed fields, then `council_size_at_proposal` and `timestamp_sec`.
  This prevents cross-action signature reuse and ambiguity.
- Signatures are Ed25519 by the root key, guard key, or council members. Council
  quorum counts signatures **deduplicated per member index**, so one key cannot be
  counted multiple times.
- **Invariants:** (a) OTA/reset timelocks must verify *elapsed time* before
  executing (do not allow an `ExecuteTimelock` shortcut that skips maturity);
  (b) quorum denominators should reflect the intended electorate, not just
  recently-active members, unless inactivity is explicitly, verifiably signaled;
  (c) the offline root/guard keys must be real (replace the shipped placeholders).
 
---
 
## 7. Canonicalization (JCS)
 
- KID documents and manifests are signed over their **JCS** form with the
  signature field omitted. JCS gives a single deterministic byte string for a
  given JSON value, so signers/verifiers on different platforms agree.
- **Invariant:** never sign or verify over a non-canonical serialization
  (e.g. `serde_json::to_string` without canonicalization) for these objects.
 
---
 
## 8. Storage at rest
 
- Keypairs encrypted with **PBKDF2**-derived keys; secrets **zeroized** after use.
- Sled KV store on native. **Invariant:** distinguish the *record cache* (safe to
  reset on corruption) from *authoritative local state* (ownership/identity — must
  fail closed on corruption, never silently reset to empty). Governance state must
  not silently reset to Founder mode on a corrupt file.
 
---
 
## 9. Things reviewers should specifically try to break
 
1. Feed a valid drand signature with mismatched `randomness` — is it rejected?
2. Submit a Reveal whose VDF challenge is derived from a *different* round/name —
   accepted?
3. Flood inbound `PutRecord` / connections — does verification stay off the
   reactor and bounded?
4. Publish a KID whose controller pubkey does **not** hash to the DID — rejected?
5. Replay an old, lower-`version` manifest — rejected?
6. Queue an OTA update then immediately `ExecuteTimelock` — does the timelock hold?
7. Corrupt/truncate the governance or ownership state file — does it fail closed?
8. Path-traversal / SSRF / DNS-rebinding against the proxy and DNS resolver.
9. Ask a wasm/mobile light client to resolve a name backed only by colluding peers
   with no valid VDF — is it accepted?
 
(These map directly to the findings in the audit reports.)
