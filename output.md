# Store Verification Logic (Part 2)

**Crate:** kinetic-network
**Stage:** 8
**Reading time:** 20 minutes
**Depends on:** docs/learn/network/02_store_verification_1.md, docs/learn/core/01_overview.md, docs/learn/verify/01_overview.md

## What Is This?

This document covers the second and final phase of the validation logic applied
by the Kinetic network when a peer attempts to insert a record into the Kademlia
Distributed Hash Table (DHT). Specifically, it documents lines 331 through 660
of the verification module, which handles the most computationally intensive and
cryptographically rigorous operations in the entire network stack.

While the first part of verification handles basic sanity checks, payload
deserialization, and the recording of lightweight commitments, this second part
acts as the primary defense mechanism against sophisticated attacks. It is
responsible for verifying the Verifiable Delay Function (VDF) proofs to confirm
that a node actually expended the required continuous computational time to
legitimately claim a domain name. This prevents Sybil attacks and name-
squatting.

Beyond domain registration, this logic also strictly enforces the rules around
identity management and content routing. It handles the cryptographic
authorization for `AuthorizedKid` (Key Identifier Documents) and
`AuthorizedManifest` payloads. It enforces the use of post-quantum cryptography
(ML-DSA signatures) for all domain operations, strictly prohibits unauthorized
updates by checking cryptographic trust chains, and prevents downgrade attacks
by enforcing monotonic versioning on manifests. In summary, this logic is the
unyielding gatekeeper that ensures identity and routing data in the Kinetic DHT
remains pristine, authorized, and cryptographically secure.

## Why Kinetic Needs This

Kinetic operates as a fully decentralized network without a central naming
authority (like ICANN) to arbitrate domain ownership or manage DNS records. If a
node wants to claim the domain `saif.kin`, there is no central server to ping to
check availability and securely assign it. This decentralized nature introduces
severe vulnerability to two primary threat vectors: frontrunning and domain
hijacking.

**1. Preventing Frontrunning via Time-Lock Puzzles (The VDF Phase):**

In a naive decentralized naming system, if you broadcast a request to register
`saif.kin`, a malicious eavesdropper on the network can see your request,
duplicate it, and broadcast their own request with a higher priority or faster
network propagation, effectively stealing the name before your request is fully
processed. To eliminate this, Kinetic requires a strict two-step Commit-and-
Reveal scheme secured by time:

- You first commit to a hashed, secret version of your request.
- Then, you must spend a predictable amount of real-world time calculating a
  Verifiable Delay Function (VDF).
- This validation logic is what enforces that rule. It checks that the VDF proof
  is mathematically sound.
- It verifies that a prior commitment actually exists in the network.
- Crucially, it ensures that the commitment is old enough to prove you didn't
  just generate it instantly.
- Because VDF calculation requires sequential, non-parallelizable computation
  that takes longer than the minimum commitment wait time, it is physically
  impossible for an attacker to observe your reveal, generate a new commitment,
  and calculate a VDF fast enough to beat you. This logic binds digital
  ownership to the physics of time.

**2. Preventing Domain Hijacking (The AuthorizedKid Phase):**

Once a domain is secured, the owner needs to publish their decentralized
identity keys and periodically rotate them for security. Without this specific
validation logic, any node could broadcast a DHT update replacing the keys for
`saif.kin` with their own, hijacking the domain:

- This logic ensures that every single update to a domain's Key Identifier
  Document (KID) is cryptographically signed.
- The signature must come from the exact key that originally claimed the domain,
  or by a key that was explicitly authorized in a previously verified update.
- It enforces an unbreakable chain of cryptographic custody.

**3. Preventing Version Rollback Attacks (The AuthorizedManifest Phase):**

The manifest maps a domain to its actual content or routing addresses (e.g., an
IPFS CID). If an attacker manages to compromise an old, revoked key, they might
attempt to republish an older version of the manifest:

- This logic explicitly extracts the version number from existing DHT records.
- It strictly enforces that any new manifest must have a version number strictly
  greater than the current one.
- This guarantees the network state only moves forward, neutralizing replay and
  rollback attacks.

## How It Works

This section breaks down the three distinct operations handled in this file,
which are executed based on the type of DHT payload being processed.

### Phase 1: VDF and Commitment Verification (Completing the Reveal)

When a node receives a `Reveal` payload, it must verify the cryptographic proof
of work to finalize a domain registration.

**Step A: Drand Signature Decoding and BLS Verification:**

-> See: kinetic-network/src/store/verification.rs:L337-L368

The system relies on Drand (a distributed randomness beacon) to provide an
unpredictable input, ensuring the VDF challenge could not be pre-computed:

- The logic first decodes the hex string of the Drand signature.
- If the network is not operating in development mode (`dev_mode`), it loads the
  hardcoded Kinetic Drand public key.
- It initializes a `drand_verify::G2PubkeyRfc` object to perform a BLS signature
  verification over the G2 elliptic curve.
- This mathematically proves that the provided Drand signature is a genuine
  product of the Drand network for the specific round (`kyn`) claimed in the
  payload.

**Step B: Constructing the Deterministic VDF Challenge:**

-> See: kinetic-network/src/store/verification.rs:L370-L382

The challenge given to the VDF engine must be uniquely bound to this specific
registration attempt. The logic uses SHA-256 to hash together four specific
components:

1. The validated Drand signature bytes (hashed into `drand_rand`).
2. The domain name being requested.
3. The user's secret cryptographic salt.
4. The user's public key.

The resulting 32-byte hash acts as the exact, unforgeable challenge that the VDF
engine must have solved.

**Step C: Enforcing the Commitment Delay via Sled:**

-> See: kinetic-network/src/store/verification.rs:L384-L418

The node constructs a database key using the `KRS_COMMIT_PREFIX` and the
calculated challenge hash. It then queries its local `sled` key-value store:

- If found, it reads the Drand round (`commit_kyn`) when the commitment was
  received.
- It uses `saturating_sub` (to prevent integer underflow panics if the network
  clock skews) to calculate the age of the commitment: `current_drand_kyn -
  commit_kyn`.
- If this age is less than the `CONSENSUS_MINIMUM_COMMIT_AGE_KYNS`, the reveal
  is rejected as too recent.
- This mechanically enforces the mandatory waiting period.

**Understanding the Dev Mode Bypass:**

-> See: kinetic-network/src/store/verification.rs:L413-L418, L423-L429

In software engineering, testing computationally intensive logic like VDF
verification can dramatically slow down CI/CD pipelines and local development:

- The code explicitly implements a `dev_mode` flag.
- When enabled, the system intentionally skips the BLS Drand verification,
  bypasses the commitment age requirement, and entirely skips the VDF
  `engine.verify()` step.
- This allows developers to simulate network behavior and domain registration in
  milliseconds rather than minutes.
- However, this is strictly gated and never enabled in the production binary.

**Step D: Mathematical VDF Proof Verification:**

-> See: kinetic-network/src/store/verification.rs:L420-L465

The logic calculates the exact number of VDF iterations required based on the
time elapsed between the commitment and the current block:

- If the payload claims fewer iterations than required, it is immediately
  rejected to save CPU cycles.
- Finally, it calls `engine.verify()` on the underlying VDF engine (provided by
  the `kyn-vdf` crate).
- If the highly complex mathematical verification of the proof against the
  challenge and iterations succeeds, the reveal is deemed legitimate.

### Phase 2: Verifying the Key Identifier Document (AuthorizedKid)

After a domain is claimed, the owner publishes an `AuthorizedKid` to establish
their decentralized identity and authorized signing keys.

**Step A: Extracting the Cryptographic Root of Trust:**

-> See: kinetic-network/src/store/verification.rs:L496-L504

The system searches the DHT for the active `NameRecord` (the validated Reveal)
for this domain. The public key embedded inside this NameRecord serves as the
absolute, unquestionable root of trust for all future domain operations.

**Step B: Post-Quantum ML-DSA Signature Validation:**

-> See: kinetic-network/src/store/verification.rs:L506-L529

Kinetic is built for a post-quantum future, utilizing the ML-DSA-65 signature
scheme:

- The logic imports the `KeyInit` and `Verifier` traits from the `ml_dsa` crate.
- It constructs a `VerifyingKey` from the NameRecord's public key.
- It extracts the `owner_signature` from the payload and verifies it against the
  `signable_bytes` of the `AuthorizedKid`.
- The `signable_bytes` function injects the `NETWORK_ID` into the hash, strictly
  preventing cross-network replay attacks.

**Step C: Genesis Binding vs. Cryptographic Update Chains:**

-> See: kinetic-network/src/store/verification.rs:L531-L563

The logic dynamically branches depending on whether a KID document already
exists in the DHT. The existing record is passed as an
`Option<&std::borrow::Cow<'_, libp2p::kad::Record>>`, utilizing Rust's Copy-on-
Write semantics to avoid unnecessary memory allocations:

- **First Publication (Genesis):** If no record exists, it executes
  `auth_kid.kid_doc.verify_genesis()`. This enforces a critical invariant: the
  Decentralized Identifier (DID) string must be the exact SHA-256 hash of the
  primary controller key defined within the document.
- **Key Rotation (Updates):** If a record already exists, it parses the old
  document. It executes
  `auth_kid.kid_doc.is_authorized_update(&old_auth_kid.kid_doc)`. This
  guarantees that the new document is signed by a key explicitly granted
  rotation privileges in the previous document.

### Phase 3: Verifying the Domain Manifest (AuthorizedManifest)

The manifest maps the abstract domain name to concrete routing data, such as
IPFS content identifiers or physical node addresses.

**Step A: Payload Signature and Structure Validation:**

-> See: kinetic-network/src/store/verification.rs:L592-L637

Similar to the KID verification, this process extracts the ML-DSA public key
from the active NameRecord and strictly verifies the post-quantum signature over
the manifest payload. It goes further by ensuring the embedded `kid_doc` is
internally valid, and that the manifest data itself is properly bound to that
specific KID document, preventing mix-and-match attacks.

**Step B: Strict Anti-Rollback Version Enforcement:**

-> See: kinetic-network/src/store/verification.rs:L639-L653

This is the critical defense against replay attacks:

- If an existing manifest is found in the DHT, the logic parses it to extract
  its `version` integer.
- It evaluates `auth_manifest.manifest.version <=
  old_manifest.manifest.version`.
- If true, the new manifest is violently rejected.
- The network state is mathematically forced to only move forward, ensuring that
  compromised older keys cannot be used to force the domain back to an outdated
  configuration.

## Key Pieces

**1. `verify_reveal` Function (VDF Check Phase)**

- **What it does:** Executes the heavy cryptographic validation for a domain
  registration attempt. It handles BLS verification of the Drand randomness,
  checks the age of the local commitment, calculates the required computational
  delay, and executes the VDF proof verification engine.
- **Where it lives:** `kinetic-network/src/store/verification.rs:L331-L465`
- **Why it matters:** This function is the primary shield against Sybil attacks
  and frontrunning. It enforces the rule that time and computation must be spent
  to claim namespace, ensuring a fair distribution of domains.

**2. `verify_authorized_kid` Function**

- **What it does:** Validates the publication and rotation of a Key Identifier
  Document. It enforces post-quantum ML-DSA signatures and verifies that updates
  follow a strict chain of cryptographic authorization.
- **Where it lives:** `kinetic-network/src/store/verification.rs:L467-L570`
- **Why it matters:** This anchors a human-readable domain to a secure
  cryptographic identity. It ensures that only the true, proven owner can
  delegate signing authority or rotate compromised keys.

**3. `verify_authorized_manifest` Function**

- **What it does:** Validates the publication of the site routing manifest. It
  verifies signatures, validates the inner identity documents, and enforces
  strictly increasing version numbers to block replay attacks.
- **Where it lives:** `kinetic-network/src/store/verification.rs:L572-L660`
- **Why it matters:** This function guarantees that when a user requests routing
  information for a domain from the DHT, they receive the most current,
  cryptographically authenticated data, completely immune to historical rollback
  attempts.

## How This Connects to the Rest of Kinetic

- **CROSS-CRATE:** `kinetic_core::constants::DRAND_PUBLIC_KEY` — This constant
  from the core crate provides the hardcoded, trusted BLS public key required to
  verify the authenticity of the Drand randomness beacon.
- **CROSS-CRATE:** `kinetic_core::types::AuthorizedKid` and `AuthorizedManifest`
  — These are the precise, strictly defined payload structures imported from the
  core types crate, carrying the signatures and documents verified in this
  module.
- **CROSS-CRATE:** `kinetic_core::constants::CONSENSUS_MINIMUM_COMMIT_AGE_KYNS`
  — Defines the absolute minimum number of Drand consensus rounds a commitment
  must exist in the database before a reveal is permitted.
- **Local Storage Dependency (`sled`):** This validation logic relies heavily on
  the local `sled` database instance (passed as the `storage` parameter) to
  query prior commitments. If the local node was offline and missed the
  commitment broadcast, it will organically reject the valid reveal.
- **VDF Engine Delegation (`kyn-vdf`):** The intensive `engine.verify()` call
  delegates the mathematical verification of the sequential delay function to
  the specialized `kyn-vdf` crate, bridging network logic with pure
  cryptography.

## Quick Reference

- **Drand Verification:** Employs BLS signatures over the G2 elliptic curve to
  authenticate the distributed randomness beacon.
- **VDF Challenge Construction:** Determined via `SHA256(drand_rand + name +
  salt + pubkey)`.
- **Commitment Age Validation:** Enforced via `current_kyn - commit_kyn >=
  MINIMUM_COMMIT_AGE`, using `saturating_sub` for safety against clock skew.
- **Cryptographic Standard:** All domain ownership operations (`AuthorizedKid`,
  `AuthorizedManifest`) exclusively utilize Post-Quantum ML-DSA-65 signatures.
- **Identity Genesis Binding:** Upon initial publication, the DID string is
  mathematically forced to equal the SHA-256 hash of the genesis controller key.
- **Chain of Custody Authorization:** During an identity update, the new
  document must possess a valid signature from a key explicitly authorized in
  the preceding document.
- **Strict Version Control:** Manifest updates are mechanically forced to
  possess a strictly higher version integer than the currently stored manifest
  to neutralize rollback attacks.

## Open Questions / Things to Revisit

- **Outdated Cryptographic Comments in Code:** Within the
`verify_authorized_kid` function, there is a fallback block designed to handle
cases where an existing record fails to parse. The source code comment at
`L560-L561` explicitly states: *"the domain owner's Ed25519 signature already
authenticated the submission above"*. However, the code immediately preceding
this block actively utilizes `ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>` (Post-
Quantum ML-DSA), not the legacy Ed25519 standard. The comment is factually out
of sync with the implementation and should be updated to accurately reflect the
post-quantum architecture.

- **Security Implications of the Parsing Fallback:** In that exact same fallback
block (`verify_authorized_kid`, `L559`), if the existing DHT record is corrupted
and fails to deserialize into a valid `AuthorizedKid` structure, the system
intentionally bypasses the strict `is_authorized_update` chain-of-custody check
and accepts the new record. While it still enforces the root ML-DSA signature
derived directly from the immutable `NameRecord`, bypassing the granular key-
rotation chain upon a parsing failure could theoretically introduce an edge
case. If an attacker can intentionally corrupt the local DHT record, they might
bypass rotation rules for delegated keys. This fallback logic warrants a
rigorous security review to ensure it does not create an exploitable loophole.

