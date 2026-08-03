# Kinetic Network — Error Code Reference

Every error in Kinetic carries a stable **protocol code** (`KIN-XXX-NNN`) that uniquely identifies the failure category across all versions of the software. Codes are permanent — once assigned, a code is never reused for a different meaning.

Each error also exposes a canonical [RFC 7807 Problem Details](https://www.rfc-editor.org/rfc/rfc7807) URI of the form:

```
https://kinetic.network/errors/KIN-XXX-NNN
```

---

## Table of Contents

| Namespace | Name | Error Type |
|---|---|---|
| [KIN-RES](#kin-res--dht-name-resolution) | DHT Name Resolution | `ResolutionError` |
| [KIN-PUB](#kin-pub--dht-record-publishing) | DHT Record Publishing | `PublishError` |
| [KIN-REG](#kin-reg--name-registration) | Name Registration Flow | `RegistrationError` |
| [KIN-VDF](#kin-vdf--verifiable-delay-function) | VDF Engine | `VdfError` |
| [KIN-GOV](#kin-gov--governance) | Council Governance | `GovernanceError` |
| [KIN-DNS](#kin-dns--dns-zone-validation) | DNS Zone Parsing | `DnsError` |
| [KIN-DRA](#kin-dra--drand-randomness-beacon) | Drand Beacon | `DrandError` |
| [KIN-IDN](#kin-idn--node-identity) | Node Identity Keys | `IdentityError` |
| [KIN-NAM](#kin-nam--name-validation) | Name Validation | `NamesError` |
| [KIN-STO](#kin-sto--local-storage) | Sled Storage Engine | `StorageError` |
| [KIN-NET](#kin-net--p2p-network-client) | P2P Network Client | `NetworkClientError` |

---

## KIN-RES — DHT Name Resolution

Errors produced during a DHT name lookup. These are returned when a node attempts to resolve a `.kin` name to its DNS zone or ownership record.

**Retryable variants:** `KIN-RES-001`, `KIN-RES-005`

---

### KIN-RES-001 — Offline

| Field | Value |
|---|---|
| **Variant** | `ResolutionError::Offline` |
| **Severity** | Warning |
| **HTTP Status** | `503 Service Unavailable` |
| **Retryable** | Yes |

**What it is:** The local Kinetic node has zero connected peers in its Kademlia routing table.

**Why it occurs:** The daemon has not yet completed bootstrap peer discovery, all configured seed nodes are unreachable, or the machine has lost network connectivity.

**What it means:** No DHT query can be made. The node is functionally isolated from the Kinetic network.

**Solution:**
- Wait for the daemon to complete peer discovery (usually within 10–30 seconds of startup).
- Check that the configured seed nodes are reachable from the machine.
- Verify the machine has a working internet connection and that no firewall is blocking the Kinetic P2P port.

---

### KIN-RES-002 — NotFound

| Field | Value |
|---|---|
| **Variant** | `ResolutionError::NotFound` |
| **Severity** | Info |
| **HTTP Status** | `404 Not Found` |
| **Retryable** | No |

**What it is:** The queried `.kin` name was not found in the DHT after polling all available peers.

**Why it occurs:** The name has never been registered, the registration has been pruned because the owner stopped publishing heartbeats, or the name is simply not yet propagated to the queried peers.

**What it means:** No authoritative record exists for this name in the network at this moment.

**Solution:**
- Confirm the name is spelled correctly (including the `.kin` suffix).
- Check that the owner's daemon is running and actively publishing heartbeat records.
- Wait a few minutes and retry — DHT propagation can take time after a fresh registration.

---

### KIN-RES-003 — VdfVerificationFailed

| Field | Value |
|---|---|
| **Variant** | `ResolutionError::VdfVerificationFailed` |
| **Severity** | Error |
| **HTTP Status** | `422 Unprocessable Entity` |
| **Retryable** | No |

**What it is:** The name was found in the DHT but one or more records returned by peers failed Wesolowski VDF proof verification.

**Why it occurs:** A peer is serving a record with a forged or corrupted VDF proof. This can indicate a malicious peer attempting to inject a fraudulent record or serious data corruption in that peer's store.

**What it means:** The records returned cannot be trusted. The resolver refused to accept them.

**Solution:**
- Retry — the DHT query may hit different peers that return valid records on the next attempt.
- If the problem persists, the name's registration may be genuinely corrupted at the network level. The legitimate owner should re-register.
- Report the peer serving invalid proofs to the Kinetic Council if you can identify it.

---

### KIN-RES-004 — Expired

| Field | Value |
|---|---|
| **Variant** | `ResolutionError::Expired` |
| **Severity** | Info |
| **HTTP Status** | `410 Gone` |
| **Retryable** | No |

**What it is:** The name was found, but its registration has passed its validity window — the owner has not published a heartbeat record within the required number of drand kyns.

**Why it occurs:** The name's owner stopped running their daemon or stopped publishing heartbeats, causing the record to age beyond the `STEAL_TARGET_ROUNDS` threshold.

**What it means:** The name is expired and eligible for thermodynamic takeover by any other miner with a higher VDF iteration count.

**Solution (owner):** Restart your Kinetic daemon immediately and ensure it stays online. Publish a fresh heartbeat to reset the expiry clock before someone else claims the name.

**Solution (resolver):** Treat the name as unresolvable for now. It may be re-registered by a new owner shortly.

---

### KIN-RES-005 — Timeout

| Field | Value |
|---|---|
| **Variant** | `ResolutionError::Timeout` |
| **Severity** | Warning |
| **HTTP Status** | `504 Gateway Timeout` |
| **Retryable** | Yes |

**What it is:** The DHT query did not return a result before the resolution deadline.

**Why it occurs:** The network is congested, the name is stored on peers that are slow to respond, or the querying node is connected to a poor set of routing peers.

**What it means:** The resolution attempt was abandoned without a definitive answer (neither found nor confirmed not-found).

**Solution:**
- Retry the resolution — transient network congestion usually resolves quickly.
- If timeouts are persistent, check the daemon's peer count and connectivity.

---

### KIN-RES-006 — Internal

| Field | Value |
|---|---|
| **Variant** | `ResolutionError::Internal` |
| **Severity** | Error |
| **HTTP Status** | `500 Internal Server Error` |
| **Retryable** | No |

**What it is:** An unexpected internal failure occurred inside the resolution engine — something that should not happen under normal operating conditions.

**Why it occurs:** A logic bug, unexpected data shape, or unrecoverable state in the node's DHT event loop.

**What it means:** The daemon encountered a programming error. The resolution cannot be completed.

**Solution:** Check daemon logs for the full error chain. File a bug report at the Kinetic repository with the `request_id` and log output.

---

## KIN-PUB — DHT Record Publishing

Errors produced when pushing a record to the DHT. These occur after local VDF proof generation, during the network `PUT` phase.

**Retryable variants:** `KIN-PUB-001`, `KIN-PUB-004`

---

### KIN-PUB-001 — Offline

| Field | Value |
|---|---|
| **Variant** | `PublishError::Offline` |
| **Severity** | Warning |
| **HTTP Status** | `503 Service Unavailable` |
| **Retryable** | Yes |

**What it is:** The node has no connected peers and cannot write to the DHT.

**Why it occurs:** Same causes as `KIN-RES-001` — no active peers in the routing table.

**What it means:** The generated record cannot be published until the node comes back online.

**Solution:** Wait for peer discovery to complete and retry the publish operation.

---

### KIN-PUB-002 — InvalidProof

| Field | Value |
|---|---|
| **Variant** | `PublishError::InvalidProof` |
| **Severity** | Error |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** The VDF proof attached to the record being published is invalid or malformed.

**Why it occurs:** The proof bytes are the wrong size, the discriminant generation failed, or the proof was generated against a different challenge than the one in the record.

**What it means:** The record was rejected before being sent to the network because it would fail verification at every peer.

**Solution:** Regenerate the VDF proof from scratch. This should happen automatically if retrying via the daemon API.

---

### KIN-PUB-003 — AlreadyOwned

| Field | Value |
|---|---|
| **Variant** | `PublishError::AlreadyOwned` |
| **Severity** | Info |
| **HTTP Status** | `409 Conflict` |
| **Retryable** | No |

**What it is:** The name being published is already owned by a different Ed25519 public key, and the new record's VDF iteration count is not high enough to displace it.

**Why it occurs:** Someone else already registered this name with a sufficiently strong VDF proof.

**What it means:** The publish was blocked. You do not own this name.

**Solution:** Choose a different name. If you believe you are the legitimate owner (e.g. you are re-publishing with your own key), ensure you are using the correct signing key and that your iteration count meets or exceeds the current owner's.

---

### KIN-PUB-004 — AllFailed

| Field | Value |
|---|---|
| **Variant** | `PublishError::AllFailed` |
| **Severity** | Warning |
| **HTTP Status** | `503 Service Unavailable` |
| **Retryable** | Yes |

**What it is:** Every DHT `PUT` attempt for this record failed — all contacted peers rejected or dropped the write.

**Why it occurs:** Network instability, all target peers simultaneously going offline, or a widespread rejection due to a protocol mismatch.

**What it means:** The record was not persisted on the network.

**Solution:** Retry after a short delay. If the problem persists, verify the daemon's peer connectivity and that the record meets current protocol requirements.

---

### KIN-PUB-005 — Rejected

| Field | Value |
|---|---|
| **Variant** | `PublishError::Rejected` |
| **Severity** | Warning |
| **HTTP Status** | `422 Unprocessable Entity` |
| **Retryable** | No |

**What it is:** The network explicitly rejected the record with a specific reason string.

**Why it occurs:** The record failed store-level validation at one or more peers — e.g. invalid signature, expired prism, or commitment mismatch.

**What it means:** The record is structurally valid but violates a network-enforced protocol rule.

**Solution:** Inspect the `reason` field in the error details. Common causes are expired drand kyns (re-commit) or a bad Ed25519 signature (check the signing key).

---

### KIN-PUB-006 — Internal

| Field | Value |
|---|---|
| **Variant** | `PublishError::Internal` |
| **Severity** | Error |
| **HTTP Status** | `500 Internal Server Error` |
| **Retryable** | No |

**What it is:** An unexpected internal error inside the publish engine.

**Solution:** Check daemon logs and file a bug report with the `request_id`.

---

## KIN-REG — Name Registration

Errors produced during the full two-phase commit → reveal name registration flow.

**Retryable variants:** `KIN-REG-002`

---

### KIN-REG-001 — InvalidName

| Field | Value |
|---|---|
| **Variant** | `RegistrationError::InvalidName` |
| **Severity** | Info |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** The submitted name contains characters or structure not permitted by Kinetic naming rules.

**Why it occurs:** The name contains uppercase letters, underscores, special characters, starts/ends with a hyphen, starts with a digit, is too long, or is a reserved/infrastructure name.

**What it means:** The name cannot be registered as-is.

**Solution:** Use only lowercase letters (`a–z`), digits (`0–9`), and internal hyphens. The name must end with `.kin` and cannot be a subname (e.g. `blog.example.kin` is not registerable directly). See [KIN-NAM errors](#kin-nam--name-validation) for specifics.

---

### KIN-REG-002 — VdfFailed

| Field | Value |
|---|---|
| **Variant** | `RegistrationError::VdfFailed` |
| **Severity** | Error |
| **HTTP Status** | `500 VDF Computation Error` |
| **Retryable** | Yes |

**What it is:** The VDF (Wesolowski) proof generation step failed during the reveal phase.

**Why it occurs:** The `chiavdf` engine panicked, the discriminant could not be created from the challenge hash, or the platform does not support the required CPU instructions.

**What it means:** The registration cannot be completed without a valid VDF proof.

**Solution:** Retry the registration. If `KIN-VDF-005` (UnsupportedPlatform) is in the error chain, the hardware is incompatible — run the daemon on a supported x86_64 or aarch64 Linux/macOS system.

---

### KIN-REG-003 — CommitmentMismatch

| Field | Value |
|---|---|
| **Variant** | `RegistrationError::CommitmentMismatch` |
| **Severity** | Error |
| **HTTP Status** | `422 Unprocessable Entity` |
| **Retryable** | No |

**What it is:** The reveal data (name + salt + payload) does not hash to the same value as the previously stored commitment.

**Why it occurs:** The reveal was constructed with different data than the commit — typically caused by a bug, a corrupted local commitment record, or an attempt to tamper with the registration.

**What it means:** Protocol invariant violated: `SHA-256(name || salt || payload) ≠ stored_commitment_hash`.

**Solution:** Start the registration process from scratch. Do not modify the commit payload between the commit and reveal phases.

---

### KIN-REG-004 — AlreadyOwned

| Field | Value |
|---|---|
| **Variant** | `RegistrationError::AlreadyOwned` |
| **Severity** | Info |
| **HTTP Status** | `409 Conflict` |
| **Retryable** | No |

**What it is:** The name was claimed by a different public key before this registration completed.

**Why it occurs:** Another miner submitted a higher-iteration VDF proof during the time between your commit and your reveal.

**What it means:** You lost the mining competition for this name.

**Solution:** Choose a different name, or increase your VDF iteration count and try again. Higher iteration counts make your claim harder to displace.

---

### KIN-REG-005 — AlreadyInProgress

| Field | Value |
|---|---|
| **Variant** | `RegistrationError::AlreadyInProgress` |
| **Severity** | Info |
| **HTTP Status** | `409 Conflict` |
| **Retryable** | No |

**What it is:** A VDF registration task is already running for this name on this daemon instance.

**Why it occurs:** The daemon enforces a single concurrent registration per name to prevent CPU exhaustion.

**What it means:** You cannot start a second parallel registration for the same name.

**Solution:** Wait for the existing registration task to complete before starting a new one.

---

### KIN-REG-006 — NetworkRejected

| Field | Value |
|---|---|
| **Variant** | `RegistrationError::NetworkRejected` |
| **Severity** | Warning |
| **HTTP Status** | `422 Unprocessable Entity` |
| **Retryable** | No |

**What it is:** The network explicitly rejected the registration record. The specific `RecordRejectReason` is included in the error details.

**Why it occurs:** Common sub-reasons include: invalid signature, insufficient VDF iterations, expired registration prism, or lost tie-break to a competing record.

**What it means:** The generated record does not meet the network's acceptance criteria.

**Solution:** Inspect the `reject_reason` field. For `InsufficientIterations` — increase your target iteration count. For `InvalidSignature` — verify your signing key matches the public key in the record. For `Expired` — re-commit with a fresh drand kyn.

---

### KIN-REG-007 — Internal

| Field | Value |
|---|---|
| **Variant** | `RegistrationError::Internal` |
| **Severity** | Error |
| **HTTP Status** | `500 Internal Server Error` |
| **Retryable** | No |

**What it is:** An unexpected internal error in the registration state machine.

**Solution:** Check daemon logs and file a bug report with the `request_id`.

---

## KIN-VDF — Verifiable Delay Function

Errors from the VDF engine (`chiavdf` Wesolowski implementation). These occur during proof generation (`evaluate`) or proof verification (`verify`).

**Retryable variants:** `KIN-VDF-002`

---

### KIN-VDF-001 — LockFileError

| Field | Value |
|---|---|
| **Variant** | `VdfError::LockFileError` |
| **Severity** | Error |
| **HTTP Status** | `503 Service Unavailable` |
| **Retryable** | No |

**What it is:** The daemon could not create the filesystem lock file used to serialize VDF tasks.

**Why it occurs:** The data directory is not writable by the daemon process, or the disk is full.

**What it means:** VDF proof generation cannot proceed safely without the serialization lock.

**Solution:** Ensure the Kinetic data directory is writable (`chmod`), check disk space, and restart the daemon.

---

### KIN-VDF-002 — LockAcquireError

| Field | Value |
|---|---|
| **Variant** | `VdfError::LockAcquireError` |
| **Severity** | Error |
| **HTTP Status** | `503 Service Unavailable` |
| **Retryable** | Yes |

**What it is:** The lock file exists but could not be acquired within the timeout — another VDF task is already running.

**Why it occurs:** The VDF prover is single-threaded by design to prevent CPU starvation. A previous task is still computing.

**What it means:** The new VDF task must wait for the current one to finish.

**Solution:** Retry after the current VDF task completes. Each registration runs one VDF task at a time.

---

### KIN-VDF-003 — DiscriminantError

| Field | Value |
|---|---|
| **Variant** | `VdfError::DiscriminantError` |
| **Severity** | Error |
| **HTTP Status** | `500 VDF Computation Error` |
| **Retryable** | No |

**What it is:** The discriminant (a large prime derived from the challenge hash) could not be generated.

**Why it occurs:** The challenge hash produced a degenerate input to the discriminant algorithm — an extremely rare edge case.

**What it means:** The VDF cannot be computed for this specific challenge.

**Solution:** Re-commit with a new drand kyn (a different salt), which will produce a different challenge hash.

---

### KIN-VDF-004 — ProofGenerationError

| Field | Value |
|---|---|
| **Variant** | `VdfError::ProofGenerationError` |
| **Severity** | Error |
| **HTTP Status** | `500 VDF Computation Error` |
| **Retryable** | No |

**What it is:** The `chiavdf` prover panicked or returned an error during sequential squaring.

**Why it occurs:** Hardware fault, OS signal interrupting the compute thread, or a bug in the underlying `chiavdf` C++ library.

**What it means:** The proof generation failed mid-computation.

**Solution:** Retry the registration. If the error is persistent, check system logs for hardware errors.

---

### KIN-VDF-005 — UnsupportedPlatform

| Field | Value |
|---|---|
| **Variant** | `VdfError::UnsupportedPlatform` |
| **Severity** | Critical |
| **HTTP Status** | `501 Not Implemented` |
| **Retryable** | No |

**What it is:** The `chiavdf` native library is not available or not supported on the current platform.

**Why it occurs:** Running on an unsupported architecture (e.g. 32-bit ARM, MIPS) or an OS without the required GMP/FLINT native library dependencies.

**What it means:** The node cannot participate in name registration on this platform.

**Solution:** Run the Kinetic daemon on a supported platform: `x86_64` or `aarch64` Linux/macOS with `chiavdf` native dependencies installed.

---

### KIN-VDF-006 — InvalidProof

| Field | Value |
|---|---|
| **Variant** | `VdfError::InvalidProof` |
| **Severity** | Error |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** A VDF proof submitted for verification is structurally invalid — wrong byte length, empty, or exceeds the maximum size.

**Why it occurs:** The proof was truncated, constructed incorrectly, or the wrong proof bytes were referenced.

**What it means:** Verification cannot even begin because the proof bytes are malformed.

**Solution:** Regenerate the proof. Do not modify proof bytes between generation and submission.

---

## KIN-GOV — Governance

Errors from the council governance engine. These are returned when a `SignedGovernanceMessage` fails validation or execution.

---

### KIN-GOV-001 — MissingRootKey

| Field | Value |
|---|---|
| **Variant** | `GovernanceError::MissingRootKey` |
| **Severity** | Critical |
| **HTTP Status** | `500 Configuration Error` |
| **Retryable** | No |

**What it is:** The `ROOT_PUBLIC_KEY_HEX` compile-time constant contains the placeholder `REPLACE_ME` or is otherwise unconfigured.

**Why it occurs:** The network was built without supplying the Kinetic Council root public key. This is a fatal build/deployment error.

**What it means:** No governance actions can be verified or executed. The daemon is in an unconfigured state.

**Solution:** Rebuild the daemon with the correct `ROOT_PUBLIC_KEY_HEX` set in `network.json` or the build environment. This key is distributed by the Kinetic Council for the production network.

---

### KIN-GOV-002 — GovernanceDisabled

| Field | Value |
|---|---|
| **Variant** | `GovernanceError::GovernanceDisabled` |
| **Severity** | Warning |
| **HTTP Status** | `403 Forbidden` |
| **Retryable** | No |

**What it is:** Governance actions are universally rejected because the network is configured in `permissionless` mode.

**Why it occurs:** The `GOVERNANCE_MODEL` compile-time constant is set to `permissionless`, meaning no centralized governance is allowed in this network instance.

**What it means:** This network does not accept governance proposals. Any attempt to submit one will fail.

**Solution:** This is expected behavior for permissionless network instances. Governance actions are only valid on networks configured with `council` or `sovereign` governance mode.

---

### KIN-GOV-003 — KeyLengthMismatch

| Field | Value |
|---|---|
| **Variant** | `GovernanceError::KeyLengthMismatch` |
| **Severity** | Error |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** A supplied public key byte slice does not match the expected length for the governance key type (ML-DSA-65 keys must be exactly 1,952 bytes).

**Why it occurs:** The key was truncated during parsing, provided in the wrong format, or the wrong key type was supplied.

**What it means:** The key is unusable and the governance action cannot be verified.

**Solution:** Ensure you are providing the correct full ML-DSA-65 public key bytes (1,952 bytes). Do not hex-decode to a shorter slice or truncate the key file.

---

### KIN-GOV-004 — StaleProposal

| Field | Value |
|---|---|
| **Variant** | `GovernanceError::StaleProposal` |
| **Severity** | Info |
| **HTTP Status** | `409 Conflict` |
| **Retryable** | No |

**What it is:** The governance proposal's timestamp is older than the allowed replay window (`MAX_AGE_SECONDS`).

**Why it occurs:** The proposal was not submitted in time after being signed, or a replay attack was attempted using an old signed message.

**What it means:** The proposal is expired and has been rejected to prevent replay attacks.

**Solution:** Create and sign a fresh governance proposal with the current timestamp.

---

### KIN-GOV-005 — TimelockNotExpired

| Field | Value |
|---|---|
| **Variant** | `GovernanceError::TimelockNotExpired` |
| **Severity** | Info |
| **HTTP Status** | `409 Conflict` |
| **Retryable** | Yes |

**What it is:** A governance action has been approved but its mandatory waiting period has not yet elapsed.

**Why it occurs:** The council governance model enforces a timelock delay between proposal approval and execution to allow the Guard key to veto dangerous actions.

**What it means:** The action is queued and valid — it just cannot be executed yet.

**Solution:** Wait for the timelock duration to expire, then resubmit the execute request.

---

### KIN-GOV-007 — NotPendingOrVetoed

| Field | Value |
|---|---|
| **Variant** | `GovernanceError::NotPendingOrVetoed` |
| **Severity** | Info |
| **HTTP Status** | `409 Conflict` |
| **Retryable** | No |

**What it is:** The action hash targeted for execution or cancellation is not in a modifiable pending state.

**Why it occurs:** The action was already executed, was never submitted, or was already vetoed and removed from the queue.

**What it means:** There is nothing to act on for this hash.

**Solution:** Check the governance state via the daemon API to confirm the action hash and its current status before submitting.

---

### KIN-GOV-016 — InsufficientSignatures

| Field | Value |
|---|---|
| **Variant** | `GovernanceError::InsufficientSignatures` |
| **Severity** | Warning |
| **HTTP Status** | `401 Unauthorized` |
| **Retryable** | Yes |

**What it is:** The governance message does not carry enough valid signatures to meet the required council quorum threshold.

**Why it occurs:** Not enough council members have signed the proposal, or some signatures failed cryptographic verification.

**What it means:** The proposal cannot be approved without reaching the threshold (majority or supermajority depending on the action type).

**Solution:** Collect additional valid council member signatures and resubmit the proposal. Verify that each signing key belongs to the current active council.

---

### KIN-GOV-019 — InvalidPremiumNameLength

| Field | Value |
|---|---|
| **Variant** | `GovernanceError::InvalidPremiumNameLength` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** A governance action attempted to grant or revoke premium status for a name that is not exactly 1 character long.

**Why it occurs:** Premium single-character names (e.g. `a.kin`, `z.kin`) are a special governance-controlled category. Only 1-character apex labels qualify.

**What it means:** The target name is not eligible for premium governance.

**Solution:** Only 1-character labels (e.g. `x.kin`) can be granted or revoked as premium names via governance.

---

### KIN-GOV-020 — InvalidInfrastructureName

| Field | Value |
|---|---|
| **Variant** | `GovernanceError::InvalidInfrastructureName` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** A governance action attempted to grant or revoke infrastructure status for a name that is not in the Category 2 list.

**Why it occurs:** Infrastructure names are hardcoded (e.g., `seed.kin`, `api.kin`). Governance proposals cannot arbitrary assign infrastructure status to normal names.

**What it means:** The target name is not eligible for Category 2 infrastructure status.

**Solution:** Only explicitly listed Category 2 labels (e.g. `seed.kin`, `docs.kin`) can be granted or revoked via this governance action.

---

## KIN-DNS — DNS Zone Validation

Errors from DNS zone payload parsing and record validation. A DNS zone is the JSON payload stored inside a Kinetic reveal record describing the owner's DNS configuration.

**Retryable variants:** None — all are deterministic validation failures.

---

### KIN-DNS-001 — NestedTooDeeply

| Field | Value |
|---|---|
| **Variant** | `DnsError::NestedTooDeeply` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** The DNS zone JSON payload contains deeply nested structures that exceed the safe recursion depth.

**Why it occurs:** An attacker or misconfigured client submitted a "JSON bomb" — a deeply nested object designed to exhaust the parser's stack.

**What it means:** The payload was rejected as a DoS prevention measure.

**Solution:** Ensure the DNS zone JSON has a flat structure. Record values should be simple strings or numbers, not deeply nested objects.

---

### KIN-DNS-002 — ParseError

| Field | Value |
|---|---|
| **Variant** | `DnsError::ParseError` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** The DNS zone payload could not be deserialized from JSON.

**Why it occurs:** The payload is malformed JSON (missing brackets, invalid escape sequences, wrong field types).

**What it means:** The zone cannot be interpreted at all.

**Solution:** Validate the JSON payload against the Kinetic DNS zone schema before publishing.

---

### KIN-DNS-003 — TooManyRecords

| Field | Value |
|---|---|
| **Variant** | `DnsError::TooManyRecords` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** The zone contains more than 50 total DNS records.

**Why it occurs:** The 50-record limit enforces the 80 KB DHT record size ceiling and prevents network bloat.

**What it means:** The zone is too large to be stored.

**Solution:** Reduce the number of records to 50 or fewer. Use wildcard (`*`) records where possible to consolidate entries.

---

### KIN-DNS-004 — InvalidLabelLength

| Field | Value |
|---|---|
| **Variant** | `DnsError::InvalidLabelLength` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** A DNS record label (the key in the zone map, e.g. `www`, `api`) is either empty or exceeds 63 characters.

**Why it occurs:** Standard DNS label length limits (RFC 1035) are enforced.

**What it means:** The label is invalid and cannot be stored.

**Solution:** Use labels between 1 and 63 characters long.

---

### KIN-DNS-005 — InvalidLabelCharacters

| Field | Value |
|---|---|
| **Variant** | `DnsError::InvalidLabelCharacters` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** A DNS record label contains characters not permitted by the DNS LDH (Letters-Digits-Hyphens) rule, or starts/ends with a hyphen.

**Why it occurs:** Labels must match `[a-z0-9_-]+` and cannot start or end with a hyphen. Underscores are allowed for DNS service labels like `_dmarc`.

**Solution:** Sanitize label names to use only alphanumeric characters, hyphens, or underscores.

---

### KIN-DNS-006 — InvalidCnameConfiguration

| Field | Value |
|---|---|
| **Variant** | `DnsError::InvalidCnameConfiguration` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** A `CNAME` record was provided on the same label alongside other records.

**Why it occurs:** RFC 1034 requires that a `CNAME` must be the sole record for its label — it cannot coexist with `A`, `TXT`, or any other record type.

**Solution:** Remove all other records from the label that has a `CNAME`, or remove the `CNAME` and use direct records instead.

---

### KIN-DNS-007 — TxtRecordTooLong

| Field | Value |
|---|---|
| **Variant** | `DnsError::TxtRecordTooLong` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** A `TXT` record value exceeds 255 bytes.

**Why it occurs:** Standard DNS `TXT` record length limit (RFC 1035 §3.3.14).

**Solution:** Split the value into multiple `TXT` records of ≤255 bytes each.

---

### KIN-DNS-008 — InvalidCnameTarget

| Field | Value |
|---|---|
| **Variant** | `DnsError::InvalidCnameTarget` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** A `CNAME` record's target value is either empty or exceeds 253 characters.

**Solution:** Ensure the CNAME target is a valid fully-qualified name of 1–253 characters.

---

### KIN-DNS-009 — InvalidPeerId

| Field | Value |
|---|---|
| **Variant** | `DnsError::InvalidPeerId` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** A `PeerId` record value could not be parsed as a valid libp2p `PeerId`.

**Why it occurs:** The string is not a valid base58-encoded multihash or a valid peer identity string.

**Solution:** Use the exact peer ID string output by `kinetic-cli peer-id` or the daemon startup log.

---

### KIN-DNS-010 — InvalidKid

| Field | Value |
|---|---|
| **Variant** | `DnsError::InvalidKid` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** A `KID` (Kinetic Identity Document) record value does not start with the required `did:kin:` prefix.

**Why it occurs:** A DID from another network (e.g. `did:eth:`, `did:web:`) was supplied, or the prefix was omitted.

**What it means:** Only `did:kin:` DIDs are accepted in Kinetic DNS zones.

**Solution:** Use a valid Kinetic DID beginning with `did:kin:`.

---

### KIN-DNS-011 — InvalidIpfsCid

| Field | Value |
|---|---|
| **Variant** | `DnsError::InvalidIpfsCid` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** An `IPFS` record value is not a valid IPFS CID — it is empty, too long (>100 chars), or does not start with `Qm` (CIDv0) or `b` (CIDv1 base32).

**Solution:** Use a valid IPFS CID obtained from `ipfs add` or your IPFS pinning service.

---

## KIN-DRA — Drand Randomness Beacon

Errors from the drand Quicknet HTTP client and kyn cache. Network kyns are the time-source for VDF commitments — every commit encodes the current kyn kyn as a salt.

**Retryable variants:** `KIN-DRA-001`, `KIN-DRA-002`, `KIN-DRA-003`, `KIN-DRA-007`, `KIN-DRA-009`

---

### KIN-DRA-001 — AllEndpointsFailed

| Field | Value |
|---|---|
| **Variant** | `DrandError::AllEndpointsFailed` |
| **Severity** | Warning |
| **HTTP Status** | `502 Bad Gateway` |
| **Retryable** | Yes |

**What it is:** All configured drand HTTP endpoints returned errors or timed out.

**Why it occurs:** The drand Quicknet network is temporarily unavailable, or all endpoints are blocked from the daemon's network.

**What it means:** No fresh kyn can be fetched. The daemon falls back to the last cached kyn for operations that permit it.

**Solution:** Retry after a short delay. Check that the machine can reach `https://drand.cloudflare.com` and the other configured endpoints.

---

### KIN-DRA-002 — Network

| Field | Value |
|---|---|
| **Variant** | `DrandError::Network` |
| **Severity** | Warning |
| **HTTP Status** | `502 Bad Gateway` |
| **Retryable** | Yes |

**What it is:** A low-level network error (DNS failure, connection refused, TLS error) when contacting a drand endpoint.

**Solution:** Check network connectivity and DNS resolution for the drand endpoint URLs.

---

### KIN-DRA-003 — HttpError

| Field | Value |
|---|---|
| **Variant** | `DrandError::HttpError` |
| **Severity** | Warning |
| **HTTP Status** | Mirrors upstream status code |
| **Retryable** | Yes |

**What it is:** The drand endpoint returned a non-2xx HTTP response.

**Why it occurs:** Upstream server errors (5xx), rate limiting (429), or authentication errors on private endpoints.

**Solution:** For 5xx — retry. For 429 — back off and retry. For 4xx — check endpoint configuration.

---

### KIN-DRA-004 — NoCachedKyn

| Field | Value |
|---|---|
| **Variant** | `DrandError::NoCachedKyn` |
| **Severity** | Warning |
| **HTTP Status** | `404 Not Found` |
| **Retryable** | No |

**What it is:** No kyn has ever been cached locally and the network is also unavailable.

**Why it occurs:** First startup without network connectivity, or the local storage was wiped.

**What it means:** The daemon cannot determine the current drand kyn. Operations that require a kyn (commit, reveal) are blocked.

**Solution:** Ensure the daemon has internet connectivity on first startup so it can fetch and cache an initial kyn.

---

### KIN-DRA-005 — Serde

| Field | Value |
|---|---|
| **Variant** | `DrandError::Serde` |
| **Severity** | Error |
| **HTTP Status** | `500 Internal Server Error` |
| **Retryable** | No |

**What it is:** JSON deserialization of the drand API response failed.

**Why it occurs:** The drand API changed its response format, or the endpoint returned a non-JSON body.

**Solution:** Update the Kinetic daemon to the latest version which tracks the drand API format.

---

### KIN-DRA-006 — Storage

| Field | Value |
|---|---|
| **Variant** | `DrandError::Storage` |
| **Severity** | Error |
| **HTTP Status** | `500 Internal Server Error` |
| **Retryable** | No |

**What it is:** A Sled storage error occurred while reading or writing the drand kyn cache.

**Solution:** Check disk space and storage integrity. See [KIN-STO errors](#kin-sto--local-storage).

---

### KIN-DRA-007 — Reqwest

| Field | Value |
|---|---|
| **Variant** | `DrandError::Reqwest` |
| **Severity** | Warning |
| **HTTP Status** | `502 Bad Gateway` |
| **Retryable** | Yes |

**What it is:** The underlying `reqwest` HTTP client returned an error (connection timeout, TLS failure, etc.).

**Solution:** Retry. If persistent, check TLS certificates and outbound firewall rules.

---

### KIN-DRA-008 — InvalidSignature

| Field | Value |
|---|---|
| **Variant** | `DrandError::InvalidSignature` |
| **Severity** | Error |
| **HTTP Status** | `422 Unprocessable Entity` |
| **Retryable** | No |

**What it is:** The BLS threshold signature in the fetched drand kyn failed mathematical verification against the Quicknet chain public key.

**Why it occurs:** The endpoint returned a forged or corrupted kyn — a serious security event.

**What it means:** The kyn cannot be trusted and was rejected.

**Solution:** The daemon will automatically retry other configured endpoints. If all endpoints return invalid signatures, the drand network itself may be compromised — do not proceed with new registrations and notify the Kinetic Council.

---

### KIN-DRA-009 — StaleKyn

| Field | Value |
|---|---|
| **Variant** | `DrandError::StaleKyn` |
| **Severity** | Warning |
| **HTTP Status** | `400 Stale Network Kyn` |
| **Retryable** | Yes |

**What it is:** The kyn returned by the endpoint is too far behind the expected kyn based on the current system clock.

**Why it occurs:** The endpoint is serving an outdated cached kyn, or the daemon's system clock is significantly ahead of the actual time.

**Solution:** Retry against a different drand endpoint. Check that the system clock is synchronized via NTP.

---

## KIN-IDN — Node Identity

Errors from loading, saving, and decrypting the ML-DSA-65 node identity key file.

**Retryable variants:** None.

---

### KIN-IDN-001 — Io

| Field | Value |
|---|---|
| **Variant** | `IdentityError::Io` |
| **Severity** | Error |
| **HTTP Status** | `500 Internal Server Error` |
| **Retryable** | No |

**What it is:** An OS-level I/O error occurred while reading or writing the `identity.key` file.

**Why it occurs:** The data directory is not writable, the file is locked by another process, or the disk is full.

**Solution:** Check file permissions on the Kinetic data directory, available disk space, and that no other process holds the file open.

---

### KIN-IDN-002 — CorruptedIdentityFile

| Field | Value |
|---|---|
| **Variant** | `IdentityError::CorruptedIdentityFile` |
| **Severity** | Error |
| **HTTP Status** | `500 Internal Server Error` |
| **Retryable** | No |

**What it is:** The `identity.key` file exists but its byte length is wrong or its content cannot be parsed as a valid ML-DSA-65 key.

**Why it occurs:** Partial write during a previous save, disk corruption, or manual modification of the file.

**What it means:** The node cannot start without a valid identity key.

**Solution:** If you have a backup of the identity key or seed phrase, restore from it. Otherwise, delete `identity.key` and restart the daemon to generate a new key. **Note: a new key means a new node identity and loss of any governance roles tied to the old key.**

---

### KIN-IDN-003 — IdentityNotFound

| Field | Value |
|---|---|
| **Variant** | `IdentityError::IdentityNotFound` |
| **Severity** | Error |
| **HTTP Status** | `404 Not Found` |
| **Retryable** | No |

**What it is:** The `identity.key` file does not exist at the expected path.

**Why it occurs:** First run (expected — daemon will generate a new key), or the data directory was moved/deleted.

**What it means:** No existing identity is present. On first run, this is automatically handled by generating a fresh key.

**Solution:** On first run, this resolves automatically. If unexpected, check that the `--data-dir` path is correct and accessible.

---

### KIN-IDN-004 — InvalidSeedPhrase

| Field | Value |
|---|---|
| **Variant** | `IdentityError::InvalidSeedPhrase` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** The provided BIP-39 mnemonic seed phrase is syntactically or semantically invalid.

**Why it occurs:** Wrong number of words, invalid BIP-39 words, incorrect checksum, or extra whitespace in the phrase.

**Solution:** Verify the seed phrase word count (12 or 24 words), ensure all words are from the BIP-39 English wordlist, and check the checksum is valid.

---

### KIN-IDN-005 — DecryptionFailed

| Field | Value |
|---|---|
| **Variant** | `IdentityError::DecryptionFailed` |
| **Severity** | Error |
| **HTTP Status** | `401 Unauthorized` |
| **Retryable** | No |

**What it is:** The identity file is encrypted and could not be decrypted with the provided passphrase.

**Why it occurs:** Wrong passphrase, corrupted encrypted payload, or a version mismatch in the encryption format.

**Solution:** Double-check the passphrase. If forgotten, restore from the seed phrase. If the file is corrupted, restore from backup.

---

## KIN-NAM — Name Validation

Errors from name structural validation. These are returned before any network operation when a submitted name violates Kinetic naming rules.

**Retryable variants:** None — all are deterministic input failures.

---

### KIN-NAM-001 — NameTooLong

| Field | Value |
|---|---|
| **Variant** | `NamesError::NameTooLong` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** The full normalized name (including `.kin` suffix) exceeds 253 characters or is empty.

**Why it occurs:** RFC 1035 §2.3.4 defines a maximum of 253 characters for a fully-qualified name.

**Solution:** Use a shorter name. The label before `.kin` must be at most 249 characters.

---

### KIN-NAM-002 — LabelTooLong

| Field | Value |
|---|---|
| **Variant** | `NamesError::LabelTooLong` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** A single dot-separated label within the name exceeds 63 characters or is empty.

**Why it occurs:** RFC 1035 §2.3.4 maximum per-label length.

**Solution:** Shorten the individual label to 63 characters or fewer.

---

### KIN-NAM-003 — InvalidCharacter

| Field | Value |
|---|---|
| **Variant** | `NamesError::InvalidCharacter` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** The name contains characters not permitted by the DNS LDH (Letters-Digits-Hyphens) rule, or has invalid hyphen/digit placement.

**Why it occurs:** Uppercase letters, underscores, special characters, names starting with a hyphen or digit, or names ending with a hyphen.

**Solution:** Use only lowercase `a–z`, digits `0–9`, and internal hyphens. The first character must be a letter. The last character must not be a hyphen.

---

### KIN-NAM-004 — ReservedName

| Field | Value |
|---|---|
| **Variant** | `NamesError::ReservedName` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** The name matches a Category 1 permanently reserved public utility name (RFC 2606 / RFC 6761).

**Why it occurs:** Names like `localhost.kin`, `test.kin`, `example.kin`, `invalid.kin` etc. are permanently locked across the network.

**What it means:** These names can never be registered by any user.

**Reserved names include:** `test`, `example`, `invalid`, `localhost`, `local`, `onion`, `arpa`, `null`, `none`, `zero`, `corp`, `lan`, `internal`.

**Solution:** Choose a different name.

---

### KIN-NAM-005 — InfrastructureName

| Field | Value |
|---|---|
| **Variant** | `NamesError::InfrastructureName` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** The name is a Category 2 Kinetic infrastructure name, locked for Council governance use only.

**Why it occurs:** Names representing critical network infrastructure are permanently protected from user mining.

**What it means:** Only the Kinetic Council can allocate these names via governance proposals.

**Infrastructure names include:** `seed`, `node`, `docs`, `dao`, `explorer`, `status`, `api`, `blog`, `rpc`.

**Solution:** Choose a different name.

---

### KIN-NAM-006 — InvalidTLD

| Field | Value |
|---|---|
| **Variant** | `NamesError::InvalidTLD` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** The submitted name does not end with the `.kin` network TLD suffix.

**Why it occurs:** A name from another TLD (`.com`, `.eth`, `.crypto`) was submitted to the Kinetic API, or the `.kin` suffix was omitted.

**Solution:** Always append `.kin` to the name (e.g. `myname.kin`).

---

### KIN-NAM-007 — NotAnApexName

| Field | Value |
|---|---|
| **Variant** | `NamesError::NotAnApexName` |
| **Severity** | Warning |
| **HTTP Status** | `400 Bad Request` |
| **Retryable** | No |

**What it is:** The submitted name is a subname (e.g. `blog.example.kin`) rather than an apex name (`example.kin`).

**Why it occurs:** Only apex `.kin` domains are registered directly in the DHT. Subdomains are managed by the apex owner via their DNS zone.

**What it means:** Subdomain registration is not supported at the DHT level.

**Solution:** Register the apex name (`example.kin`) and then configure the subname (`blog.example.kin`) inside that domain's DNS zone payload.

---

## KIN-STO — Local Storage

Errors from the Sled embedded B-tree database used for all local persistence (kyn cache, commitments, governance state).

---

### KIN-STO-001 — DatabaseLocked

| Field | Value |
|---|---|
| **Variant** | `StorageError::DatabaseLocked` |
| **Severity** | Critical |
| **HTTP Status** | `423 Locked` |
| **Retryable** | No |

**What it is:** The Sled database file is locked by another process — a second Kinetic daemon instance is already running and holding an exclusive lock.

**Why it occurs:** Two daemon instances sharing the same data directory, or a previous daemon instance crashed without releasing the lock.

**What it means:** This daemon instance cannot start. Sled does not support concurrent access.

**Solution:** Stop the other daemon instance first. If no other instance is running, delete the lock file from the data directory (usually `{data_dir}/db/sled.lock`) and restart.

---

### KIN-STO-002 — Corruption

| Field | Value |
|---|---|
| **Variant** | `StorageError::Corruption` |
| **Severity** | Error |
| **HTTP Status** | `500 Storage Corruption` |
| **Retryable** | No |

**What it is:** Sled detected structural corruption in the database file.

**Why it occurs:** Unclean shutdown during a write, disk hardware failure, or filesystem corruption.

**What it means:** The local state is untrustworthy.

**Solution:** Stop the daemon. Back up the data directory. Delete the database and restart — the daemon will resync state from the network. If this happens repeatedly, check the underlying disk health with `smartctl`.

---

### KIN-STO-003 — OperationFailed

| Field | Value |
|---|---|
| **Variant** | `StorageError::OperationFailed` |
| **Severity** | Error |
| **HTTP Status** | `500 Storage Operation Failed` |
| **Retryable** | Yes |

**What it is:** A read, write, or delete operation on the Sled database failed.

**Why it occurs:** Disk full, I/O error, or a transient Sled internal error.

**Solution:** Check disk space and I/O health. Retry the operation. If persistent, see `KIN-STO-002` guidance.

---

## KIN-NET — P2P Network Client

Errors from the `KineticNetworkClient` — the internal interface between the daemon's business logic and the libp2p Kademlia / GossipSub event loop.

**Retryable variants:** `KIN-NET-001`, `KIN-NET-002`, `KIN-NET-003`, `KIN-NET-005`

---

### KIN-NET-001 — Timeout

| Field | Value |
|---|---|
| **Variant** | `NetworkClientError::Timeout` |
| **Severity** | Warning |
| **HTTP Status** | `504 Gateway Timeout` |
| **Retryable** | Yes |

**What it is:** A DHT query or stream operation exceeded its deadline.

**Why it occurs:** Network congestion, slow peers, or high system load on the daemon's machine.

**Solution:** Retry. Increase the operation timeout in the daemon configuration if timeouts are consistently too aggressive for your network conditions.

---

### KIN-NET-002 — Offline

| Field | Value |
|---|---|
| **Variant** | `NetworkClientError::Offline` |
| **Severity** | Warning |
| **HTTP Status** | `503 Service Unavailable` |
| **Retryable** | Yes |

**What it is:** The local node is unreachable — no active peers in the routing table.

**Solution:** Wait for bootstrap peer discovery to complete.

---

### KIN-NET-003 — RoutingTableEmpty

| Field | Value |
|---|---|
| **Variant** | `NetworkClientError::RoutingTableEmpty` |
| **Severity** | Warning |
| **HTTP Status** | `503 Service Unavailable` |
| **Retryable** | Yes |

**What it is:** The Kademlia routing table has zero entries — the node knows no peers at all.

**Why it occurs:** The daemon just started and has not yet contacted any seed nodes, or all seed nodes are unreachable.

**Solution:** Wait for seed node contact. Verify seed node addresses are correctly configured in `network.json`.

---

### KIN-NET-004 — ChannelClosed

| Field | Value |
|---|---|
| **Variant** | `NetworkClientError::ChannelClosed` |
| **Severity** | Error |
| **HTTP Status** | `500 Internal Server Error` |
| **Retryable** | No |

**What it is:** The internal `mpsc`/`oneshot` channel between the API handler and the libp2p event loop was closed unexpectedly.

**Why it occurs:** The network event loop task panicked or was killed, causing its receiving end to drop.

**What it means:** The daemon's network layer is in a broken state.

**Solution:** Restart the daemon. If this occurs frequently, check for panics in the daemon logs and file a bug report.

---

### KIN-NET-005 — StreamDropped

| Field | Value |
|---|---|
| **Variant** | `NetworkClientError::StreamDropped` |
| **Severity** | Warning |
| **HTTP Status** | `504 Gateway Timeout` |
| **Retryable** | Yes |

**What it is:** A remote peer closed the libp2p stream before the response was fully delivered.

**Why it occurs:** Peer went offline mid-transfer, or the peer's connection was unstable.

**Solution:** Retry — the query will be routed to a different peer on the next attempt.

---

### KIN-NET-006 — UnsupportedProtocol

| Field | Value |
|---|---|
| **Variant** | `NetworkClientError::UnsupportedProtocol` |
| **Severity** | Error |
| **HTTP Status** | `501 Not Implemented` |
| **Retryable** | No |

**What it is:** The remote peer does not speak the required Kinetic protocol version.

**Why it occurs:** The remote peer is running a significantly older or incompatible version of the Kinetic daemon.

**What it means:** This peer cannot be used for Kinetic operations.

**Solution:** Ensure all nodes in your peer list are running a compatible version of the Kinetic daemon.

---

### KIN-NET-007 — GossipSubError

| Field | Value |
|---|---|
| **Variant** | `NetworkClientError::GossipSubError` |
| **Severity** | Warning |
| **HTTP Status** | `502 Bad Gateway` |
| **Retryable** | No |

**What it is:** A GossipSub publish or subscribe operation failed.

**Why it occurs:** No peers are subscribed to the required GossipSub topic, or the message exceeded the GossipSub message size limit.

**Solution:** Ensure the message is within size limits and that the daemon has active peers subscribed to the relevant topic.

---

### KIN-NET-008 — StoreError

| Field | Value |
|---|---|
| **Variant** | `NetworkClientError::StoreError` |
| **Severity** | Error |
| **HTTP Status** | `500 Internal Server Error` |
| **Retryable** | No |

**What it is:** The Kademlia record store rejected a `PUT` or returned an error for a `GET`.

**Why it occurs:** The record failed local store validation (signature, VDF proof) or the store is at capacity.

**Solution:** Check the specific store error message in the details. Verify the record is valid before publishing.

---

### KIN-NET-009 — Other

| Field | Value |
|---|---|
| **Variant** | `NetworkClientError::Other` |
| **Severity** | Error |
| **HTTP Status** | `500 Internal Server Error` |
| **Retryable** | No |

**What it is:** A miscellaneous network error that does not fit any specific category.

**Solution:** Check daemon logs for the error message string. File a bug report if the error is reproducible and consistently triggers this code.

---

*Last updated: kinetic-core audit cycle. All codes are stable and permanent — once assigned, a code is never reused for a different meaning.*
