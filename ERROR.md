# Kinetic Error Taxonomy (KIN)

## 1. Introduction

The Kinetic network utilizes a strictly typed, globally unique error taxonomy designed to eliminate ambiguity. Unlike traditional networks that obscure failures behind generic HTTP codes or raw OS errors, Kinetic maps every protocol rejection, cryptographic fault, and state machine violation to a stable `KIN-XXX-NNN` identifier. 

This master dictionary serves as the definitive reference for node operators, client developers, and protocol engineers. We believe that an error is not merely a stack trace—it is a domain-driven API contract. To that end, this document provides deep, actionable context for every error, consistently broken down into:

* **What**: The exact technical failure that occurred at the protocol boundary.
* **Why**: The architectural or security context that forced the failure.
* **Fix**: Actionable mitigation steps for developers and node operators to resolve the issue.

### 1.1. Anatomy of an Error Code

Error codes are deterministically structured to provide immediate operational context: 
`KIN-[SUBSYSTEM]-[CODE]`

* **`KIN`**: The global Kinetic protocol prefix.
* **`[SUBSYSTEM]`**: A 3-letter namespace denoting the architectural domain where the fault originated. 
* **`[CODE]`**: A 3-digit numeric identifier uniquely mapped to a specific Rust enum variant (e.g., `001`).

**Architectural Domains:**
* **`KIN-DBE`**: Embedded Storage Engine & State Database (`redb`)
* **`KIN-QRY`**: Kademlia DHT & Network Transport
* **`KIN-RND`**: Drand Randomness Beacon & Threshold Cryptography
* **`KIN-SYS`**: Daemon Lifecycle & Host System Resources
* **`KIN-TEL`**: Telemetry, Tracing & Logging Subsystem
* **`KIN-VER`**: Core Cryptographic Verifiers (Ed25519 & ML-DSA-65)
* **`KIN-KID`**: Kinetic Identity Documents & W3C DID Constraints
* **`KIN-API`**: REST API Gateway & Middlewares
* **`KIN-RVL`**: Proof of Sequential Work (VDF) & Commit-Reveal Engine
* **`KIN-ACN`**: Governance, Proposals & Treasury Actions
* **`KIN-SEC`**: Middlebox Security, SSRF Protection & IP Banning
* **`KIN-GTW`**: IPFS Storage Gateway Integration
* **`KIN-NRS`**: Kinetic Name Resolution System & Zone Configuration
* **`KIN-NAM`**: Apex Name Validation & Punycode Normalization
* **`KIN-CFG`**: Node Configuration & TOML Parsing

### 1.2. API Response Format (RFC 7807)

When interacting with the Kinetic daemon via its REST API or Web2 Bridge, all errors are strictly serialized according to the **RFC 7807 Problem Details for HTTP APIs** standard. This ensures that downstream clients can parse and handle errors programmatically without relying on brittle regex matching against error strings.

```json
{
  "type": "https://docs.kinetic.host/errors/KIN-DBE-001",
  "title": "DatabaseLocked",
  "status": 500,
  "detail": "Another instance of Kinetic daemon is already running (Database is locked).",
  "severity": "Critical",
  "retryable": false
}
```

* **`type`**: A dereferenceable URI pointing directly to the documentation for this specific error.
* **`title`**: The exact Rust Enum variant name that triggered the error (e.g. `DatabaseLocked`).
* **`status`**: The contextual HTTP status code (mapped automatically from the error context).
* **`detail`**: A clean, human-readable user message. Internal backend paths, cryptographic jargon, and raw OS traces are intentionally scrubbed from this field to prevent information leakage.
* **`severity`**: The log level classification (Warning, Error, Critical).
* **`retryable`**: A deterministic boolean flag. If `true`, the client application can safely re-attempt the exact same request after applying a standard exponential backoff delay.

### 1.3. Severity Levels & Node Telemetry

Every error is rigorously classified by a severity level. This classification dictates how the daemon routes the event through its internal OpenTelemetry and tracing pipelines.

| Severity | Operational Meaning | Daemon Action |
| :--- | :--- | :--- |
| **Info** | Normal protocol outcome, not a fault. | Emits `tracing::info!`. No operational action needed. (e.g., Target DHT peer is offline). |
| **Warning** | Transient condition or bad user input. | Emits `tracing::warn!`. Self-recovering. (e.g., Client provided an invalid CID format). |
| **Error** | Unexpected failure, protocol violation, or state mismatch. | Emits `tracing::error!`. Requires developer investigation. (e.g., Tampered ML-DSA-65 signature). |
| **Critical** | Liveness threat or fatal system fault. | Emits `tracing::error!` and often triggers an immediate, safe panic/shutdown to protect state. (e.g., Database locked, Treasury key missing). |

---

## KIN-DBE - StorageError

**Underlying Type:** `StorageError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-DBE-001` | `DatabaseLocked` | **What:** The daemon attempted to open the embedded database file, but it is exclusively locked.<br>**Why:** The embedded storage engine requires an exclusive lock to prevent data corruption.<br>**Fix:** This typically means a second instance of the Kinetic daemon is already running on this machine. Kill the other process. |
| `KIN-DBE-002` | `Corruption` | **What:** The database engine detected structural corruption in the B-tree on disk.<br>**Why:** This can happen after a hard power loss or disk failure.<br>**Fix:** The node may need to wipe its state and re-sync from the network. |
| `KIN-DBE-003` | `ReadFailed` | **What:** The local node failed to read a value from the database engine.<br>**Why:** This could indicate underlying disk issues or unreadable sectors.<br>**Fix:** Check the host filesystem health and disk space. |
| `KIN-DBE-004` | `WriteFailed` | **What:** The local node failed to write a value to the database engine.<br>**Why:** The operating system rejected the write syscall.<br>**Fix:** Ensure the disk is not completely full and the daemon has write permissions. |
| `KIN-DBE-005` | `DeleteFailed` | **What:** The local node failed to delete a record from the database.<br>**Why:** The database engine encountered an internal IO error during the transaction.<br>**Fix:** Ensure the disk is not completely full and the daemon has write permissions. |
| `KIN-DBE-006` | `ScanFailed` | **What:** The local node failed to iterate over a range of keys in the database.<br>**Why:** The underlying B-tree cursor encountered an IO error.<br>**Fix:** Check the host filesystem health. |
| `KIN-DBE-007` | `OpenFailed` | **What:** The daemon failed to initialize or create the database engine at startup.<br>**Why:** The OS rejected the file creation or read operations.<br>**Fix:** Check the filesystem permissions and ensure the target directory exists. |
| `KIN-DBE-008` | `DeserializationFailed` | **What:** The record was found but could not be parsed.<br>**Why:** The payload is malformed or incompatible with the current daemon version.<br>**Fix:** Upgrade your Kinetic daemon. |
| `KIN-DBE-011` | `InvalidRecordDiscarded` | **What:** During node startup, the Kinetic Record Store (KRS) detected an invalid or expired NameRecord on disk.<br>**Why:** The node aggressively purges expired records to save space.<br>**Fix:** The daemon safely discarded it automatically. No action is required. |
| `KIN-DBE-012` | `OrphanedHeartbeatPurged` | **What:** During node startup, the Kinetic Record Store (KRS) detected a heartbeat for a name that no longer exists.<br>**Why:** The parent NameRecord was previously dropped or expired.<br>**Fix:** The daemon safely purged the orphan automatically. No action is required. |

---

## KIN-QRY - NetworkClientError

**Underlying Type:** `NetworkClientError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-QRY-005` | `Timeout` | **What:** The DHT resolution query timed out.<br>**Why:** The network is congested or the target peers are offline.<br>**Fix:** Retry the resolution query. |
| `KIN-QRY-001` | `Offline` | **What:** The local node has no reachable peers.<br>**Why:** The P2P swarm is disconnected from the mesh and cannot route messages.<br>**Fix:** Verify your internet connection and ensure bootstrap nodes are reachable. |
| `KIN-QRY-001` | `RoutingTableEmpty` | **What:** The Kademlia routing table contains no known peers.<br>**Why:** The node is online but hasn't successfully discovered any peers yet.<br>**Fix:** Wait for the initial bootstrap process to complete. |
| `KIN-QRY-006` | `ChannelClosed` | **What:** The internal mpsc/oneshot channel between the caller and the network loop was closed.<br>**Why:** The network loop crashed or the daemon is in the middle of a shutdown sequence.<br>**Fix:** Check the daemon logs for panic traces in the P2P subsystem. |
| `KIN-RPC-001` | `GossipSubError` | **What:** A GossipSub publish or subscribe operation failed.<br>**Why:** The node attempted to broadcast a message to a topic but failed, potentially due to missing peers.<br>**Fix:** Wait for the mesh to fully form before broadcasting to GossipSub topics. |
| `KIN-RPC-002` | `Other` | **What:** A catch-all for miscellaneous network errors.<br>**Why:** An unexpected low-level P2P or TCP/QUIC stream error occurred.<br>**Fix:** Examine the appended error string for more details. |

---

## KIN-QRY - RecordRejectReason

**Underlying Type:** `RecordRejectReason`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-QRY-XXX` | `InvalidSignature` | **What:** The ML-DSA-65 or Ed25519 signature on the record is invalid.<br>**Why:** The record was tampered with or signed by the wrong key.<br>**Fix:** Ensure you are signing the canonicalized payload correctly. |
| `KIN-QRY-XXX` | `InvalidVdf` | **What:** The embedded VDF proof failed cryptographic verification.<br>**Why:** A peer attempted to submit a forged or malformed proof of time.<br>**Fix:** Ensure your local RSA VDF engine is generating valid proofs. |
| `KIN-QRY-XXX` | `Expired` | **What:** The record has expired.<br>**Why:** The TTL or expiration timestamp has passed, so the network dropped it.<br>**Fix:** Generate a fresh record with a new expiration date. |
| `KIN-QRY-XXX` | `AlreadyOwned` | **What:** The name is already owned by a different identity key.<br>**Why:** Another user has a valid registration for this name in the DHT.<br>**Fix:** You must choose a different, unregistered name. |
| `KIN-QRY-XXX` | `InsufficientIterations` | **What:** The VDF iteration count is below the minimum required for this name and kyn.<br>**Why:** The submitter did not compute the VDF for a long enough time.<br>**Fix:** Ensure the client enforces the global dynamic difficulty floor. |
| `KIN-QRY-XXX` | `TieBroken` | **What:** The record lost an XOR-distance tie-break to a competing record.<br>**Why:** Two valid commitments were submitted for the same name at the exact same kyn.<br>**Fix:** The network resolved the tie cryptographically. Try registering again in the next epoch. |
| `KIN-QRY-XXX` | `CommitmentMismatch` | **What:** The revealed data's hash did not match the previously published commitment.<br>**Why:** A different payload was submitted during the reveal phase.<br>**Fix:** You must restart the entire 2-phase registration process. |
| `KIN-QRY-XXX` | `InvalidDrandHex` | **What:** The `drand_signature` field contains non-hex characters.<br>**Why:** The string must be fully parseable into raw bytes.<br>**Fix:** All signature proofs must be strictly hex-encoded strings. |
| `KIN-QRY-XXX` | `InvalidPublicKey` | **What:** The public key bytes could not be parsed as a valid cryptographic key.<br>**Why:** A malformed key cannot be used for cryptographic checks.<br>**Fix:** The key is either the wrong length or cryptographically invalid (e.g. malformed Ed25519 or ML-DSA-65 key). |
| `KIN-QRY-XXX` | `MalformedSignature` | **What:** The signature bytes are the wrong length or otherwise malformed.<br>**Why:** Signature algorithms require precise byte bounds.<br>**Fix:** The signature must match the expected byte length for the record's underlying algorithm. |

---

## KIN-QRY - ResolutionError

**Underlying Type:** `ResolutionError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-QRY-001` | `Offline` | **What:** The local node has no connected peers and cannot reach the DHT.<br>**Why:** The P2P swarm must be connected to at least one bootstrap or regular peer to resolve names.<br>**Fix:** Check your internet connection or verify that bootstrap nodes are online. |
| `KIN-QRY-XXX` | `NotFound` | **What:** The requested record could not be found in the DHT.<br>**Why:** The record may have expired or was never registered.<br>**Fix:** Ensure the name or CID is correct. |
| `KIN-QRY-XXX` | `VdfVerificationFailed` | **What:** The name was found but one or more of the returned records failed VDF verification.<br>**Why:** A peer returned a payload with a cryptographically invalid proof of time.<br>**Fix:** The malicious records were discarded. If all records fail, the name cannot be safely resolved. |
| `KIN-QRY-XXX` | `Expired` | **What:** The record has expired.<br>**Why:** The TTL or expiration timestamp has passed, so the network dropped it.<br>**Fix:** Generate a fresh record with a new expiration date. |
| `KIN-QRY-XXX` | `Timeout` | **What:** The DHT resolution query timed out.<br>**Why:** The network is congested or the target peers are offline.<br>**Fix:** Retry the resolution query. |
| `KIN-QRY-XXX` | `Internal` | **What:** An unexpected internal error occurred during the publish flow.<br>**Why:** A localized crash, parse failure, or channel panic occurred inside the Kademlia handler.<br>**Fix:** Check the daemon logs for stack traces and ensure the database isn't corrupted. |
| `KIN-QRY-XXX` | `SignatureVerificationFailed` | **What:** The record's signature failed cryptographic verification (spoofed/tampered).<br>**Why:** A peer attempted to route a malicious record posing as the apex owner.<br>**Fix:** The record was safely dropped. |

---

## KIN-QRY - PublishError

**Underlying Type:** `PublishError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-QRY-001` | `Offline` | **What:** The local node has no connected peers and cannot write to the DHT.<br>**Why:** The publish operation requires a live P2P mesh to broadcast the record.<br>**Fix:** Check your internet connection or verify that bootstrap nodes are online. |
| `KIN-QRY-XXX` | `InvalidProof` | **What:** The VDF proof attached to the record failed verification.<br>**Why:** You attempted to publish a record with a corrupted, forged, or insufficient proof of time.<br>**Fix:** Ensure your node successfully generates a valid RSA VDF proof before publishing. |
| `KIN-QRY-XXX` | `AlreadyOwned` | **What:** The name is already owned by a different identity key.<br>**Why:** Another user has a valid registration for this name in the DHT.<br>**Fix:** You must choose a different, unregistered name. |
| `KIN-QRY-XXX` | `AllFailed` | **What:** Every DHT `PUT` attempt for this record failed.<br>**Why:** The network is heavily congested or peers are refusing to store the record.<br>**Fix:** Wait a few minutes and try publishing again. |
| `KIN-QRY-XXX` | `Rejected` | **What:** The record was rejected by the store.<br>**Why:** The DHT nodes validated the payload and found it cryptographically or temporally invalid.<br>**Fix:** Ensure your local clock is synced and your signature keys are correct. |
| `KIN-QRY-XXX` | `Internal` | **What:** An unexpected internal error occurred during the publish flow.<br>**Why:** A localized crash, parse failure, or channel panic occurred inside the Kademlia handler.<br>**Fix:** Check the daemon logs for stack traces and ensure the database isn't corrupted. |
| `KIN-QRY-XXX` | `QuorumFailed` | **What:** The network did not reach the required replication quorum during resolution.<br>**Why:** Not enough peers returned matching records to establish trust.<br>**Fix:** Retry the resolution query. |
| `KIN-QRY-XXX` | `QuorumCheckError` | **What:** The quorum verification check failed due to a network error.<br>**Why:** The node lost connection to the DHT while verifying the quorum.<br>**Fix:** Retry the publish operation. |
| `KIN-QRY-XXX` | `ZonePublishFailed` | **What:** A lower-level network error occurred while publishing the zone record.<br>**Why:** This could be a timeout or stream failure.<br>**Fix:** Retry the publish operation. |
| `KIN-QRY-XXX` | `CommitmentQuorumFailed` | **What:** The network did not reach the required replication quorum for the commitment.<br>**Why:** Too few peers stored the pre-registration commitment.<br>**Fix:** Retry the registration process. |
| `KIN-QRY-XXX` | `CommitmentQuorumCheckError` | **What:** The quorum verification check failed for the commitment due to a network error.<br>**Why:** The node lost connection to the DHT while verifying the quorum.<br>**Fix:** Retry the registration process. |
| `KIN-QRY-XXX` | `CommitmentPublishFailed` | **What:** Failed to publish the commitment to the DHT.<br>**Why:** This could be a timeout or stream failure.<br>**Fix:** Retry the registration process. |
| `KIN-QRY-XXX` | `MissingLocalRevealForKid` | **What:** Local reveal could not be found to verify the AuthorizedKid locally.<br>**Why:** The local state is missing the required reveal payload.<br>**Fix:** The node will forward it anyway, but the network might reject it. |
| `KIN-QRY-XXX` | `MissingLocalRevealForManifest` | **What:** Local reveal could not be found to verify the AuthorizedManifest locally.<br>**Why:** The local state is missing the required reveal payload.<br>**Fix:** The node will forward it anyway, but the network might reject it. |
| `KIN-QRY-XXX` | `ZoneSerializationFailed` | **What:** The zone payload failed to serialize into JSON.<br>**Why:** The zone data contains unsupported types or circular references.<br>**Fix:** Ensure the zone data strictly adheres to the schema. |
| `KIN-QRY-XXX` | `HostRoutingRecordPublishFailed` | **What:** Failed to broadcast the dynamic HostRoutingRecord to the DHT.<br>**Why:** This could be a timeout or stream failure.<br>**Fix:** Retry the broadcast operation. |
| `KIN-QRY-XXX` | `KidPublishFailed` | **What:** Failed to publish the KID document to the DHT.<br>**Why:** This could be a timeout or stream failure.<br>**Fix:** Retry the publish operation. |
| `KIN-QRY-XXX` | `ManifestPublishFailed` | **What:** Failed to publish the Manifest to the DHT.<br>**Why:** This could be a timeout or stream failure.<br>**Fix:** Retry the publish operation. |

---

## KIN-QRY - RegistrationError

**Underlying Type:** `RegistrationError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-QRY-XXX` | `InvalidName` | **What:** The name provided is invalid.<br>**Why:** It contains illegal characters or exceeds length limits.<br>**Fix:** Only use lowercase alphanumeric characters and hyphens. |
| `KIN-QRY-XXX` | `VdfFailed` | **What:** The VDF computation step failed.<br>**Why:** The RSA Proof of Sequential Work engine encountered a mathematical or execution error.<br>**Fix:** Check system resources and restart the daemon. |
| `KIN-QRY-XXX` | `CommitmentMismatch` | **What:** The revealed data's hash did not match the previously published commitment.<br>**Why:** A different payload was submitted during the reveal phase.<br>**Fix:** You must restart the entire 2-phase registration process. |
| `KIN-QRY-XXX` | `AlreadyOwned` | **What:** The name is already owned by a different identity key.<br>**Why:** Another user has a valid registration for this name in the DHT.<br>**Fix:** You must choose a different, unregistered name. |
| `KIN-QRY-XXX` | `AlreadyInProgress` | **What:** A VDF task for this name is already running; only one at a time is permitted.<br>**Why:** VDF generation is extremely CPU intensive.<br>**Fix:** Wait for the current registration to complete. |
| `KIN-QRY-XXX` | `NetworkRejected` | **What:** The network rejected the registration record for the stated reason.<br>**Why:** The DHT nodes validated the payload and found it cryptographically or temporally invalid.<br>**Fix:** Correct the payload and retry. |
| `KIN-QRY-XXX` | `Internal` | **What:** An unexpected internal error occurred during the publish flow.<br>**Why:** A localized crash, parse failure, or channel panic occurred inside the Kademlia handler.<br>**Fix:** Check the daemon logs for stack traces and ensure the database isn't corrupted. |
| `KIN-QRY-XXX` | `NotRegisteredLocal` | **What:** The requested `.kin` name is not registered on this node.<br>**Why:** The node does not hold the private keys required to update or manage this name.<br>**Fix:** You can only manage names that were registered on this specific node. |

---

## KIN-RND - DrandError

**Underlying Type:** `DrandError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-RND-001` | `AllEndpointsFailed` | **What:** All configured endpoints returned errors or timed out.<br>**Why:** The node could not fetch the latest drand beacon from any of the public HTTP endpoints.<br>**Fix:** Ensure your node has outbound internet access or provide custom drand endpoint URLs. |
| `KIN-RND-003` | `HttpError` | **What:** An endpoint returned a non-2xx HTTP status.<br>**Why:** The public drand League of Entropy relays might be experiencing downtime or rate-limiting you.<br>**Fix:** Try adding alternate endpoints to your daemon configuration. |
| `KIN-RND-004` | `NoCachedKyn` | **What:** No kyn was found in the local cache (and the network is also unavailable).<br>**Why:** The node needs a recent kyn to bootstrap its clock, but none was saved and the internet is down.<br>**Fix:** Connect to the internet briefly so the node can cache the latest beacon. |
| `KIN-RND-005` | `Serde` | **What:** JSON (de)serialization failed.<br>**Why:** An endpoint returned a malformed response that did not match the expected drand schema.<br>**Fix:** This may indicate a Man-in-the-Middle attack or a broken API endpoint. |
| `KIN-RND-006` | `Storage` | **What:** A storage engine error occurred while reading or writing the cache.<br>**Why:** The daemon lacks permissions to write to its data directory, or the disk is full.<br>**Fix:** Ensure the storage directory is writable. |
| `KIN-RND-007` | `HttpClient` | **What:** An HTTP client error from the network library.<br>**Why:** DNS resolution failed, the connection timed out, or TLS negotiation failed.<br>**Fix:** Check your internet connection and system DNS settings. |
| `KIN-RND-008` | `InvalidSignature` | **What:** The ML-DSA-65 or Ed25519 signature on the record is invalid.<br>**Why:** The record was tampered with or signed by the wrong key.<br>**Fix:** Ensure you are signing the canonicalized payload correctly. |
| `KIN-RND-XXX` | `StaleKyn` | **What:** The returned record's kyn timestamp is too old compared to the system clock.<br>**Why:** The record is considered stale and is no longer trustworthy.<br>**Fix:** The owner must publish a fresh record. |
| `KIN-RND-XXX` | `StreamReadFailed` | **What:** A network stream reading error occurred.<br>**Why:** The connection to the endpoint dropped mid-download while reading the beacon payload.<br>**Fix:** Retry the fetch operation. |
| `KIN-RND-XXX` | `ResponseTooLarge` | **What:** The endpoint returned a response body exceeding the maximum allowed size.<br>**Why:** A malicious endpoint tried to exhaust the node's memory with an infinitely long response.<br>**Fix:** The connection was terminated safely. |
| `KIN-RND-XXX` | `UnavailableOnStartup` | **What:** The drand beacon was unavailable when the node started up.<br>**Why:** The node cannot initialize its internal clock without a valid drand round.<br>**Fix:** The node will fail to start until it can reach a drand endpoint. |
| `KIN-RND-XXX` | `P2pFallbackTriggered` | **What:** The node fell too far behind and triggered the P2P drand fallback mechanism.<br>**Why:** The node's clock drifted too far from the network's clock.<br>**Fix:** The node is now relying on P2P peers to catch up. |
| `KIN-RND-XXX` | `DevModeMockKyn` | **What:** Dev mode warning: returning a mock kyn because the cache was empty.<br>**Why:** You passed the `--dev` flag which bypassed hard timing guarantees.<br>**Fix:** Disable dev mode in production. |
| `KIN-RND-XXX` | `RegistrationDisabled` | **What:** Registration is disabled because the beacon could not be reached.<br>**Why:** The node strictly refuses to mint time-locked identities without a synchronized clock.<br>**Fix:** Check the internet connection. |
| `KIN-RND-XXX` | `LiveFetchFailedFallback` | **What:** Live fetch failed, gracefully falling back to local cached kyn.<br>**Why:** The Drand endpoints are unreachable but we have recent state.<br>**Fix:** No immediate action required. |

---

## KIN-SYS - SystemError

**Underlying Type:** `SystemError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-SYS-001` | `PortInUse` | **What:** Failed to bind to a required network port (EADDRINUSE).<br>**Why:** The node attempted to bind the HTTP or P2P socket to a port that is already taken.<br>**Fix:** Stop any conflicting processes or change the port in the configuration. |
| `KIN-SYS-002` | `NetworkHotswapFailed` | **What:** Failed to hot-swap the libp2p network backend.<br>**Why:** The runtime attempted to migrate the network layer (e.g. Quic to TCP) but encountered an OS error.<br>**Fix:** The node must be fully restarted to recover the network interface. |
| `KIN-SYS-003` | `ServerCrashed` | **What:** A background daemon or API server exited unexpectedly.<br>**Why:** A localized panic or unhandled error occurred in one of the async worker pools.<br>**Fix:** Check the daemon logs for a stack trace. |
| `KIN-SYS-004` | `IdentityCorrupted` | **What:** A required static identity or host key on disk is missing, invalid, or corrupted.<br>**Why:** The daemon cannot start without its cryptographic identity.<br>**Fix:** Restore the keyfile from backup or let the daemon generate a fresh identity. |
| `KIN-SYS-005` | `KeychainStorageFailed` | **What:** Failed to store credentials in the OS Keychain/Keyring.<br>**Why:** The daemon attempted to securely store API tokens but was blocked by the OS.<br>**Fix:** Ensure dbus/keyring services are running, or fall back to plaintext file storage. |
| `KIN-SYS-006` | `DiskPersistenceFailed` | **What:** Failed to persist infrastructure state or config to disk.<br>**Why:** The daemon lacks permissions to write to its data directory, or the disk is full.<br>**Fix:** Ensure the app directory is writable by the daemon's user. |
| `KIN-SYS-007` | `ServiceManagerError` | **What:** Failed to interact with the native OS service manager (systemd, launchd, winsw).<br>**Why:** The CLI could not start, stop, or install the Kinetic background service.<br>**Fix:** Ensure you are running with administrator/root privileges. |
| `KIN-SYS-008` | `InvalidOsEnvironment` | **What:** The OS environment or filesystem paths are invalid (e.g., non-UTF8 paths, arg parse failures).<br>**Why:** The daemon was launched in a broken or highly restrictive terminal environment.<br>**Fix:** Ensure environment variables like `$HOME` are valid UTF-8 strings. |
| `KIN-SYS-009` | `PrivilegeDropFailed` | **What:** Failed to drop system privileges (setuid/setgid).<br>**Why:** The daemon attempted to drop root privileges for security, but the syscall failed.<br>**Fix:** Ensure the target unprivileged user exists on the system. |
| `KIN-SYS-010` | `LoopbackSetupFailed` | **What:** Failed to setup OS loopback interface (macOS alias).<br>**Why:** The daemon could not bind to the secondary loopback IP required for local proxying.<br>**Fix:** Ensure `ifconfig lo0 alias` can be run, or reboot the OS. |
| `KIN-SYS-011` | `MutexPoisoned` | **What:** A global concurrency mutex was poisoned during a panic.<br>**Why:** A thread crashed while holding a critical global lock, corrupting shared state.<br>**Fix:** The daemon must be restarted to safely recover. |
| `KIN-SYS-012` | `TrustInstallationFailed` | **What:** Failed to install the Root CA into the OS system trust store.<br>**Why:** The node attempted to install the TLS intercept root cert, but was blocked by the OS.<br>**Fix:** Follow the manual installation instructions in the Kinetic UI, or run as administrator. |
| `KIN-SYS-013` | `CaRotationFailed` | **What:** Local Root CA is expiring or auto-rotation failed.<br>**Why:** The node could not generate a new Root CA or clean up the old one from the OS.<br>**Fix:** Manually delete the `~/.kinetic/certs` folder and restart the daemon. |
| `KIN-SYS-014` | `SigIntBindingFailed` | **What:** Failed to bind to the SIGINT (Ctrl+C) keyboard signal.<br>**Why:** The OS prevented the daemon from intercepting keyboard interrupts.<br>**Fix:** The daemon may not shut down gracefully when terminated via terminal. |
| `KIN-SYS-015` | `SigTermBindingFailed` | **What:** Failed to bind to the POSIX SIGTERM signal.<br>**Why:** The OS prevented the daemon from intercepting standard termination requests.<br>**Fix:** The daemon may not shut down gracefully during system reboots or service stops. |

---

## KIN-TEL - TelemetryError

**Underlying Type:** `TelemetryError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-TEL-001` | `MissingCorrelationId` | **What:** A network function requested a correlation ID, but no async tracing scope was initialized.<br>**Why:** This happens if a network operation is spawned outside of the main HTTP router tracing span.<br>**Fix:** Ensure all tasks are properly instrumented with `#[tracing::instrument]`. |
| `KIN-TEL-002` | `BroadcastFailed` | **What:** Failed to broadcast telemetry data to the network.<br>**Why:** The node could not push its periodic health metrics to the diagnostic mesh.<br>**Fix:** Check your P2P connections or disable telemetry in the config if not desired. |

---

## KIN-VER - SignatureVerifyError

**Underlying Type:** `SignatureVerifyError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-VER-001` | `MalformedPublicKey` | **What:** Malformed Public Key. The provided byte array is not a valid ML-DSA-65 public key.<br>**Why:** The public key may be truncated, corrupted, or formatted for a different cryptographic scheme.<br>**Fix:** Ensure the key is exactly the length required by ML-DSA-65 and generated correctly. |
| `KIN-VER-002` | `MalformedSignature` | **What:** The signature bytes are the wrong length or otherwise malformed.<br>**Why:** Signature algorithms require precise byte bounds.<br>**Fix:** The signature must match the expected byte length for the record's underlying algorithm. |
| `KIN-VER-003` | `InvalidSignature` | **What:** The ML-DSA-65 or Ed25519 signature on the record is invalid.<br>**Why:** The record was tampered with or signed by the wrong key.<br>**Fix:** Ensure you are signing the canonicalized payload correctly. |
| `KIN-VER-004` | `DelegatedCapabilityMissing` | **What:** Delegated Capability Missing. The delegated manifest does not grant the required capability.<br>**Why:** An entity attempted an action (like publishing a record) without the correct capability listed in the manifest.<br>**Fix:** The apex owner must update the manifest to explicitly grant this capability. |
| `KIN-VER-005` | `DelegatedAuthorizationInvalid` | **What:** Delegated Authorization Invalid. The delegated authorization proof is structurally invalid or fails signature check.<br>**Why:** The proof chain linking the delegate to the apex owner is broken or cryptographically forged.<br>**Fix:** Ensure the delegate was actually authorized by the current apex owner. |
| `KIN-VER-006` | `DelegatedScopeViolation` | **What:** Delegated Scope Violation. The delegated manifest name scope does not match the target name.<br>**Why:** A delegate attempted to perform an action on a name they are not authorized to manage.<br>**Fix:** Double check the domain name in the manifest matches the target resource exactly. |
| `KIN-VER-007` | `DelegatedKidDocumentMissing` | **What:** Delegated KID Document Missing. The delegated manifest is missing the required KID document.<br>**Why:** In order to verify the delegation chain, the apex owner's identity document must be included.<br>**Fix:** Include the full, signed KID document in the delegated request. |

---

## KIN-KID - Error

**Underlying Type:** `Error`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-KID-001` | `InvalidDidPrefix` | **What:** The provided DID string does not start with the expected `did:kin:` prefix.<br>**Why:** The Kinetic identity system strictly requires all identifiers to follow the W3C DID specification format for the `kin` method.<br>**Fix:** Prepend the 64-character identity hash with `did:kin:`. |
| `KIN-KID-002` | `Reserved002` | **What:** Reserved error code (KIN-KID-002).<br>**Why:** This code is explicitly kept empty to maintain backward compatibility in the error taxonomy.<br>**Fix:** This error should never be encountered in production. |
| `KIN-KID-003` | `InvalidDidHexLength` | **What:** The method-specific ID portion of the DID is not exactly 64 characters long.<br>**Why:** Kinetic uses SHA-256 hashes for method IDs, which map strictly to 64 hexadecimal characters.<br>**Fix:** Ensure you are passing a complete, untruncated SHA-256 hash in the DID string. |
| `KIN-KID-004` | `InvalidDidHexCharacters` | **What:** The method-specific ID contains invalid characters.<br>**Why:** To prevent encoding ambiguity, the method ID must strictly contain only lowercase hexadecimal characters (0-9, a-f).<br>**Fix:** Convert any uppercase hex characters to lowercase and remove any spaces or special characters. |
| `KIN-KID-005` | `JsonParseError` | **What:** The identity document or capability manifest could not be parsed from JSON.<br>**Why:** The payload is malformed, missing required fields, or has incorrect data types.<br>**Fix:** Ensure the payload is a correctly formatted JSON object adhering to the DID Document specification. |
| `KIN-KID-006` | `CanonicalizationError` | **What:** The daemon failed to apply JCS (JSON Canonicalization Scheme) to the identity document.<br>**Why:** Canonicalization is strictly required before cryptographic signing to ensure the byte representation is deterministic across platforms.<br>**Fix:** This usually indicates a deeply nested or malformed JSON payload that breaks RFC 8785 rules. |
| `KIN-KID-007` | `InvalidSignature` | **What:** The ML-DSA-65 or Ed25519 signature on the record is invalid.<br>**Why:** The record was tampered with or signed by the wrong key.<br>**Fix:** Ensure you are signing the canonicalized payload correctly. |
| `KIN-KID-008` | `MissingSignature` | **What:** The Identity Document or capability manifest is missing a required `proof` signature field.<br>**Why:** By protocol design, all identity mutations and manifests must be cryptographically authenticated by the controller.<br>**Fix:** You must attach a valid ML-DSA-65 signature proof to the document before publishing. |
| `KIN-KID-009` | `Base64Error` | **What:** The daemon failed to decode a base64-encoded cryptographic key or signature.<br>**Why:** The string contains invalid characters, is missing padding, or uses standard base64 instead of the required base64url encoding.<br>**Fix:** Ensure all cryptographic fields strictly use standard base64url encoding without padding. |
| `KIN-KID-010` | `StringLengthExceeded` | **What:** A string field in the document exceeds the maximum allowed byte length.<br>**Why:** The network enforces strict string length bounds to prevent memory exhaustion attacks via massive payloads.<br>**Fix:** Reduce the length of the specified field to comply with protocol limits. |
| `KIN-KID-011` | `UnauthorizedManifestSignature` | **What:** The capability manifest was signed by a key that is not authorized in the parent KID document.<br>**Why:** The network strictly verifies the delegation chain to ensure only authorized controllers can emit capability manifests.<br>**Fix:** Verify that the signing key is officially listed as an active `assertionMethod` controller in the root KID Document. |
| `KIN-KID-012` | `KeyLimitExceeded` | **What:** The Identity Document contains more keys than the maximum allowed limit (20).<br>**Why:** This strict upper bound ensures fast cryptographic validation across the network and prevents state bloat.<br>**Fix:** You must prune the identity document to remove unused or deprecated keys. |
| `KIN-KID-016` | `ServiceLimitExceeded` | **What:** The capability manifest contains more service endpoints than the maximum allowed limit (50).<br>**Why:** This strict upper bound ensures fast DHT replication and prevents network bloat.<br>**Fix:** Remove unused or redundant service endpoints to comply with the network bounds. |
| `KIN-KID-017` | `LocationLimitExceeded` | **What:** The Identity Document contains more manifest pointers than the maximum allowed limit (20).<br>**Why:** This strict upper bound ensures fast DHT replication and prevents network bloat.<br>**Fix:** Remove unused capability locations to comply with the network bounds. |
| `KIN-KID-013` | `InvalidValidFrom` | **What:** The capability manifest's `valid_from` timestamp is set in the future.<br>**Why:** To prevent timing attacks and desync issues, capabilities cannot become valid at a future date.<br>**Fix:** Ensure the issuer's system clock is synchronized via NTP and recreate the manifest. |
| `KIN-KID-014` | `ManifestExpired` | **What:** The capability manifest's expiration timestamp has passed.<br>**Why:** Capabilities are strictly time-bound to ensure keys and access rights can be reliably rotated.<br>**Fix:** A new, freshly signed capability manifest must be generated and published. |
| `KIN-KID-015` | `DidKeyMismatch` | **What:** The Genesis DID does not match the SHA-256 hash of the primary controller key.<br>**Why:** The initial DID must always be cryptographically bound to its root key to prevent hijacking during network bootstrap.<br>**Fix:** Ensure the DID is exactly `did:kin:<sha256_of_key>`. |

---

## KIN-KID - Severity

**Underlying Type:** `Severity`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |

---

## KIN-API - RestApiError

**Underlying Type:** `RestApiError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-API-001` | `InvalidToken` | **What:** The client failed to provide a valid Bearer token in the Authorization header.<br>**Why:** The daemon requires authentication for this endpoint, but the request was missing a token or provided an incorrect one.<br>**Fix:** Ensure you pass the `Authorization: Bearer <token>` header, matching the token defined in your `kinetic.toml` config file. |
| `KIN-API-002` | `SseStreamLagged` | **What:** A Server-Sent Events (SSE) subscriber lagged behind and skipped messages.<br>**Why:** The client consuming the SSE event stream is processing events slower than the daemon is emitting them, overflowing the internal channel buffer.<br>**Fix:** Ensure your client loop does not block when processing events, or increase the channel buffer size if burst traffic is expected. |
| `KIN-API-003` | `ResponseTooLarge` | **What:** An internal client received an API response that exceeded the maximum safety limit.<br>**Why:** To prevent memory exhaustion attacks, the daemon strictly limits the maximum size of incoming payload responses.<br>**Fix:** This usually indicates an upstream anomaly. No direct action is required unless the daemon is failing to resolve legitimate records. |
| `KIN-API-004` | `InsufficientPrivileges` | **What:** The client provided a valid token but lacks the correct Role to perform this action.<br>**Why:** The endpoint requires an elevated permission tier (e.g., attempting a write operation with a read-only token).<br>**Fix:** Update the daemon's API token configuration in `kinetic.toml` to grant `Write` or `Admin` privileges to this token. |
| `KIN-API-005` | `NotFound` | **What:** The requested record could not be found in the DHT.<br>**Why:** The record may have expired or was never registered.<br>**Fix:** Ensure the name or CID is correct. |
| `KIN-API-006` | `BadRequest` | **What:** The REST API rejected the request payload or URL parameters.<br>**Why:** The client provided malformed JSON, missing required fields, or used the endpoint incorrectly.<br>**Fix:** Review the accompanying error string and the API documentation to ensure your request matches the expected schema. |

---

## KIN-RVL - RevealValidationError

**Underlying Type:** `RevealValidationError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-RVL-001` | `InvalidProtocolVersion` | **What:** The protocol version is unsupported.<br>**Why:** The network rejected the version string.<br>**Fix:** Upgrade your daemon. |
| `KIN-RVL-XXX` | `InvalidName` | **What:** The name provided is invalid.<br>**Why:** It contains illegal characters or exceeds length limits.<br>**Fix:** Only use lowercase alphanumeric characters and hyphens. |
| `KIN-RVL-002` | `PayloadTooLarge` | **What:** The payload size exceeds the protocol maximum.<br>**Why:** We strictly enforce size caps on VDFs to prevent memory attacks.<br>**Fix:** Trim your payload size. |
| `KIN-RVL-003` | `InvalidDrandSignatureLength` | **What:** The Drand signature length is incorrect.<br>**Why:** Drand uses BLS signatures that are strictly 96 bytes.<br>**Fix:** Send a valid BLS signature. |
| `KIN-RVL-004` | `InvalidPubkeyLength` | **What:** The ML-DSA public key length is incorrect.<br>**Why:** It must be exactly the expected ML-DSA-65 size.<br>**Fix:** Send the correct key bytes. |
| `KIN-RVL-005` | `InvalidSignatureLength` | **What:** The ML-DSA signature length is incorrect.<br>**Why:** It must be exactly 3309 bytes.<br>**Fix:** Send a valid ML-DSA-65 signature. |
| `KIN-RVL-006` | `VdfProofTooLarge` | **What:** The VDF proof size exceeds the maximum allowed length.<br>**Why:** RSA proofs cannot be unbounded in length.<br>**Fix:** The node dropped the malicious VDF proof. |

---

## KIN-RVL - VdfRejectReason

**Underlying Type:** `VdfRejectReason`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-RVL-XXX` | `MalformedProof` | **What:** The proof byte array was the wrong size or could not be parsed.<br>**Why:** The VDF engine rejected the format.<br>**Fix:** Ensure the RSA proof is valid. |
| `KIN-RVL-XXX` | `ChallengeMismatch` | **What:** The proof verified successfully, but for a different challenge than expected.<br>**Why:** The node caught a replay attack or mismatched inputs.<br>**Fix:** Reject the proof. |
| `KIN-RVL-XXX` | `EngineError` | **What:** The underlying VDF verifier threw an internal error.<br>**Why:** Mathematical or GMP library failure.<br>**Fix:** Check daemon logs. |
| `KIN-RVL-XXX` | `DiscriminantFailed` | **What:** Generating the discriminant from the challenge failed.<br>**Why:** The hash-to-prime step rejected the input bytes.<br>**Fix:** Invalid challenge was dropped. |

---

## KIN-RVL - VdfError

**Underlying Type:** `VdfError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-RVL-XXX` | `LockFileError` | **What:** The filesystem could not create the lock file needed to serialize VDF tasks.<br>**Why:** Permission denied or disk full.<br>**Fix:** Ensure write permissions on the `.gemini` dir. |
| `KIN-RVL-XXX` | `LockAcquireError` | **What:** A timeout or OS error occurred while attempting to acquire the VDF lock.<br>**Why:** Another heavy task is hogging the CPU.<br>**Fix:** Wait for it to finish. |
| `KIN-RVL-XXX` | `DiscriminantError` | **What:** Generating the discriminant from the challenge failed.<br>**Why:** The prime generation step failed.<br>**Fix:** Ensure valid cryptographic inputs. |
| `KIN-RVL-XXX` | `ProofGenerationError` | **What:** The underlying VDF prover threw an internal error or panicked.<br>**Why:** Engine failure during the tight loop.<br>**Fix:** Check system resources and logs. |
| `KIN-RVL-XXX` | `UnsupportedPlatform` | **What:** The current architecture or OS is not supported by the embedded VDF library.<br>**Why:** Requires a 64-bit platform with proper mathematical libraries.<br>**Fix:** Run on supported hardware. |
| `KIN-RVL-XXX` | `InvalidProof` | **What:** The VDF proof attached to the record failed verification.<br>**Why:** You attempted to publish a record with a corrupted, forged, or insufficient proof of time.<br>**Fix:** Ensure your node successfully generates a valid RSA VDF proof before publishing. |
| `KIN-RVL-XXX` | `InvalidChallenge` | **What:** The challenge is degenerate (e.g. all-zero) and would produce a universally-forgeable proof.<br>**Why:** Prevent trivial bypass of the time lock.<br>**Fix:** Rejected immediately. |
| `KIN-RVL-XXX` | `MaxIterationsExceeded` | **What:** The requested iterations exceed the maximum allowed for a user VDF task.<br>**Why:** Prevent absolute CPU exhaustion.<br>**Fix:** Request a smaller iterations cap. |
| `KIN-RVL-XXX` | `TooManyTasks` | **What:** The node is already processing the maximum number of concurrent VDF tasks.<br>**Why:** Limits physical CPU burnout and DDoS vectors.<br>**Fix:** Try again later. |

---

## KIN-ACN - GovernanceError

**Underlying Type:** `GovernanceError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-ACN-001` | `MissingRootKey` | **What:** **What**: The daemon started in Sovereign mode but the `ROOT_PUBLIC_KEY_HEX` environment variable is missing.<br>**Why:** **Why**: The daemon requires the root public key at startup to verify incoming governance actions.<br>**Fix:** **Fix**: Ensure the `ROOT_PUBLIC_KEY_HEX` environment variable is set to a valid 64-character hex string. |
| `KIN-ACN-002` | `MalformedRootKey` | **What:** **What**: The `ROOT_PUBLIC_KEY_HEX` environment variable contains invalid characters or is incorrectly padded.<br>**Why:** **Why**: The daemon failed to decode the hex string into raw ML-DSA-65 bytes.<br>**Fix:** **Fix**: Verify the key is exactly 64 valid hexadecimal characters. |
| `KIN-ACN-004` | `KeyLengthMismatch` | **What:** The public key or signature bytes are the wrong length.<br>**Why:** You passed Ed25519 bytes to an ML-DSA-65 verifier or vice-versa.<br>**Fix:** Ensure you are using the correct cryptographic suite. |
| `KIN-ACN-005` | `StaleProposal` | **What:** **What**: The proposed governance action is older than the current network head timestamp.<br>**Why:** **Why**: The node rejects historical actions to prevent time-delay and replay attacks.<br>**Fix:** **Fix**: This action was discarded. If you are the issuer, ensure your local clock is synced via NTP before signing. |
| `KIN-ACN-006` | `AlreadyExecuted` | **What:** **What**: A governance action with a specific ID has already been executed and recorded in the local state.<br>**Why:** **Why**: The network strictly deduplicates actions based on their cryptographic signature to prevent immediate replay attacks.<br>**Fix:** **Fix**: This action was safely ignored. No further action is required. |
| `KIN-ACN-003` | `GovernanceDisabled` | **What:** **What**: A governance action was received, but the node is running in permissionless mode.<br>**Why:** **Why**: In permissionless testnets or specific deployments, global governance actions are universally rejected.<br>**Fix:** **Fix**: The node safely dropped the message. Ensure you are targeting the correct network ID. |
| `KIN-ACN-007` | `InvalidSignature` | **What:** The ML-DSA-65 or Ed25519 signature on the record is invalid.<br>**Why:** The record was tampered with or signed by the wrong key.<br>**Fix:** Ensure you are signing the canonicalized payload correctly. |
| `KIN-ACN-008` | `InvalidPrimeLength` | **What:** **What**: A prime name mapping or unmapping was attempted on a name that is not exactly 1 character long.<br>**Why:** **Why**: By protocol definition, Prime names (e.g., `a.kin`) are strictly reserved and must be exactly one character.<br>**Fix:** **Fix**: Correct your governance payload to target a 1-character name. |
| `KIN-ACN-009` | `InvalidProtocolName` | **What:** **What**: A protocol name mapping was attempted on a name that is not whitelisted in the Category 2 protocols list.<br>**Why:** **Why**: Category 2 names (e.g., `seed.kin`, `docs.kin`) are strictly defined in the protocol schema.<br>**Fix:** **Fix**: Ensure your governance payload targets a valid, recognized protocol name. |
| `KIN-ACN-010` | `AlreadyMapped` | **What:** **What**: A governance action attempted to map a name that is already currently mapped.<br>**Why:** **Why**: The state transition is invalid. Overwriting an active mapping directly is forbidden to prevent accidental hijacking.<br>**Fix:** **Fix**: You must explicitly unmap the name first by publishing a revocation action before remapping it. |
| `KIN-ACN-011` | `NotMapped` | **What:** **What**: A governance action attempted to revoke or unmap a name that does not exist in the current state.<br>**Why:** **Why**: The state transition is invalid as there is no active mapping to remove.<br>**Fix:** **Fix**: Verify the current governance state using the local REST API before issuing revocations. |
| `KIN-ACN-XXX` | `"Name payloads in governance actions must be strictly normalized` | **What:** **What**: The name payload in the governance action was unnormalized.<br>**Why:** **Why**: Payloads must be strictly normalized (no `.kin` suffix, strictly lowercase) before being signed to ensure deterministic verification.<br>**Fix:** **Fix**: Use the `kinetic_types::names::normalize` function before signing your governance payload. |
| `KIN-ACN-012` | `UnnormalizedName` | **What:** Name string contains uppercase letters or illegal symbols.<br>**Why:** Names must be cleanly normalized before hashing.<br>**Fix:** Lowercase the string. |
| `KIN-ACN-013` | `StateSaveFailed` | **What:** **What**: The daemon could not persist the updated governance state to disk.<br>**Why:** **Why**: The file system may be read-only, or the daemon process lacks necessary write permissions.<br>**Fix:** **Fix**: Check disk space and permissions for the `base_dir/networks/nsp-salt_id/` directory. |
| `KIN-ACN-014` | `P2pPublishFailed` | **What:** **What**: The local node successfully verified the action, but could not broadcast it to the P2P network.<br>**Why:** **Why**: The GossipSub publish operation failed due to a lack of connected peers or a saturated network queue.<br>**Fix:** **Fix**: Verify your node is well-connected to the mesh before issuing administrative actions. |
| `KIN-ACN-015` | `InvalidSeedState` | **What:** **What**: A bootstrap seed node provided governance bytes that failed decoding or validation.<br>**Why:** **Why**: The seed node may be running an incompatible protocol version or attempting to distribute a malicious state.<br>**Fix:** **Fix**: The node disconnected from the seed and will try another. Ensure your configured bootstrap nodes are trustworthy. |
| `KIN-ACN-016` | `StateCorrupted` | **What:** **What**: The local governance JSON state file on disk is corrupted and cannot be parsed.<br>**Why:** **Why**: A previous write operation was interrupted by a power loss or crash, leaving partial JSON bytes.<br>**Fix:** **Fix**: The daemon will refuse to start to avoid overwriting valid network state. You must manually delete the corrupted file and let it resync. |
| `KIN-ACN-017` | `StateReadFailed` | **What:** **What**: The local governance file could not be read.<br>**Why:** **Why**: The file is missing, locked by another process, or has incorrect OS permissions.<br>**Fix:** **Fix**: Ensure the daemon user has read access to the data directory. |
| `KIN-ACN-018` | `BootstrapFetchFailed` | **What:** **What**: The node failed to pull the initial governance state from any bootstrap peers.<br>**Why:** **Why**: All configured bootstrap nodes are offline, unreachable, or returning invalid states.<br>**Fix:** **Fix**: The node cannot join the network without a valid initial state. Check your internet connection and bootstrap configuration. |

---

## KIN-SEC - SecurityError

**Underlying Type:** `SecurityError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-SEC-001` | `Loopback` | **What:** The IP address provided or resolved is a local loopback address (e.g., 127.0.0.1 or ::1).<br>**Why:** The proxy strictly prohibits connecting to the local machine to prevent Server-Side Request Forgery (SSRF).<br>**Fix:** The request was dropped. Do not attempt to route proxy traffic back into the local node. |
| `KIN-SEC-002` | `Private` | **What:** The IP address is in a private subnet (e.g., 10.0.0.0/8, 192.168.0.0/16).<br>**Why:** The proxy blocks connections to private LAN IPs to prevent attackers from mapping or exploiting internal networks.<br>**Fix:** The request was dropped. |
| `KIN-SEC-003` | `Unspecified` | **What:** The IP address is the unspecified address (e.g., 0.0.0.0 or ::).<br>**Why:** Connecting to the unspecified address can sometimes bypass OS-level firewalls or route to localhost.<br>**Fix:** The request was dropped. |
| `KIN-SEC-004` | `CgNat` | **What:** The IP address is inside a Carrier-Grade NAT block (e.g., 100.64.0.0/10).<br>**Why:** CGNAT addresses are typically not publicly routable and can be abused to exploit ISP infrastructure.<br>**Fix:** The request was dropped. |
| `KIN-SEC-005` | `LocalNetworkRouting` | **What:** The IP address routes locally via multicast, broadcast, or link-local routing.<br>**Why:** These addresses target the local network segment and are prohibited to prevent lateral network scanning.<br>**Fix:** The request was dropped. |
| `KIN-SEC-006` | `Ipv6MappedExploit` | **What:** The IP address is an IPv6 address that maps or translates directly to an internal IPv4 address.<br>**Why:** This is a common SSRF technique to bypass naive IPv4 filtering by encapsulating the attack payload in IPv6.<br>**Fix:** The request was dropped. |
| `KIN-SEC-007` | `Nat64` | **What:** The IP address uses NAT64 translation to mask an internal destination.<br>**Why:** NAT64 blocks can be abused to bypass IP filtering logic.<br>**Fix:** The request was dropped. |
| `KIN-SEC-008` | `Reserved` | **What:** The IP address is a reserved, experimental, or documentation address block.<br>**Why:** These addresses are not meant for public internet routing and are blocked to adhere to RFC 6890.<br>**Fix:** The request was dropped. |
| `KIN-SEC-009` | `NrsSsrfBlocked` | **What:** An NRS DNS resolution returned an A/AAAA record that points to a forbidden, internal IP address.<br>**Why:** An attacker registered a Kinetic domain pointing to a local IP to trick the proxy into launching an SSRF attack.<br>**Fix:** The DNS resolution and request were immediately dropped. |
| `KIN-SEC-010` | `PathTraversalAttempt` | **What:** The HTTP proxy blocked a malicious path traversal attempt (e.g., `../`).<br>**Why:** Path traversal sequences can be used to escape routing boundaries and access unauthorized files or endpoints.<br>**Fix:** Ensure all requested proxy paths are properly normalized. |
| `KIN-SEC-011` | `PayloadTooLarge` | **What:** The payload size exceeds the protocol maximum.<br>**Why:** We strictly enforce size caps on VDFs to prevent memory attacks.<br>**Fix:** Trim your payload size. |
| `KIN-SEC-012` | `InvalidMethod` | **What:** The HTTP method is unsupported or blocked by the proxy layer.<br>**Why:** The proxy only supports standard web methods to prevent exotic HTTP verb smuggling.<br>**Fix:** Use a standard HTTP method (GET, POST, PUT, DELETE, PATCH). |
| `KIN-SEC-013` | `BackendResponseTooLarge` | **What:** The upstream backend server returned a response payload that exceeds the maximum safety limit.<br>**Why:** The proxy limits the size of forwarded responses to prevent the upstream server from exhausting the node's memory.<br>**Fix:** The connection to the backend was terminated. Ensure the upstream service pages or chunks large responses. |
| `KIN-SEC-014` | `DangerousIpBlocked` | **What:** The Web2 proxy bridge resolved a target host to a dangerous or internal IP address.<br>**Why:** Even in standard Web2 mode, the daemon prevents you from inadvertently proxying traffic into malicious infrastructure.<br>**Fix:** The request was dropped. |
| `KIN-SEC-015` | `DevModePrivateIp` | **What:** The daemon is running in Dev Mode and allowed proxy forwarding to a private IP address.<br>**Why:** This warning is emitted to remind developers that this behavior is intentionally insecure and strictly for local testing.<br>**Fix:** Disable `--dev` flag in production environments. |
| `KIN-SEC-016` | `ProxyLoop` | **What:** The proxy detected a loop attempting to connect to the node's own backend port.<br>**Why:** Proxying traffic back into the daemon's own proxy or API ports causes infinite loops and resource exhaustion.<br>**Fix:** The request was dropped. Ensure external routing logic does not resolve to the local Kinetic node. |

---

## KIN-GTW - GatewayError

**Underlying Type:** `GatewayError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-GTW-001` | `ProxyingToGateway` | **What:** The proxy is routing an IPFS request to a designated storage gateway.<br>**Why:** The node intercepted an `ipfs://` protocol request and is translating it to a standard HTTP gateway request.<br>**Fix:** This is an informational telemetry event. No action is required. |
| `KIN-GTW-002` | `GatewayFailedWithStatus` | **What:** A specific storage gateway returned an HTTP failure status (e.g., 404 Not Found, 502 Bad Gateway).<br>**Why:** The gateway is online but could not locate the requested CID on the IPFS network before timing out.<br>**Fix:** The node will automatically fall back and attempt the next configured gateway in the list. |
| `KIN-GTW-003` | `GatewayUnreachable` | **What:** A specific storage gateway was completely unreachable due to a network or transport error.<br>**Why:** The gateway may be offline, its domain may have expired, or a firewall is blocking the connection.<br>**Fix:** The node will automatically fall back and attempt the next configured gateway in the list. |
| `KIN-GTW-004` | `AllGatewaysFailed` | **What:** All configured storage gateways failed to resolve the target CID.<br>**Why:** The requested file is likely no longer pinned or hosted anywhere on the global IPFS network.<br>**Fix:** The proxy request failed. Ensure the IPFS CID is still actively pinned by a storage provider. |

---

## KIN-NRS - NrsError

**Underlying Type:** `NrsError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-NRS-002` | `ParseError` | **What:** The NRS JSON payload could not be deserialized into a valid `NrsZone` struct.<br>**Why:** The JSON is malformed, has unexpected types (e.g. integer instead of string), or is missing required fields.<br>**Fix:** Ensure the payload is valid JSON and perfectly matches the Kinetic NRS schema. |
| `KIN-NRS-003` | `TooManyRecords` | **What:** The zone contains more than the maximum allowed number of records (50).<br>**Why:** This strict upper bound ensures zones stay well within the 80 KB limit for fast DHT replication and parsing.<br>**Fix:** You must prune the zone file. Consolidate records or remove unnecessary subdomains. |
| `KIN-NRS-004` | `InvalidLabelLength` | **What:** A record label is either empty or exceeds 62 characters in length.<br>**Why:** NRS record labels must strictly adhere to RFC 1035 length limits to maintain downstream DNS compatibility.<br>**Fix:** Break the label up or choose a shorter name. |
| `KIN-NRS-005` | `InvalidLabelCharacters` | **What:** A record label contains invalid characters.<br>**Why:** NRS labels are strictly enforced using the LDH (Letters, Digits, Hyphen) rule to prevent homograph attacks.<br>**Fix:** Ensure labels contain only lowercase alphanumeric characters and internal hyphens. No emojis or spaces. |
| `KIN-NRS-006` | `InvalidCnameConfiguration` | **What:** A CNAME record was defined on a label alongside other routing records (like A or AAAA).<br>**Why:** Per DNS RFC 1034, a CNAME must be the exclusive routing record for its label. (Note: Cryptographic KID records are allowed alongside CNAMEs).<br>**Fix:** Remove the conflicting A/AAAA/IPFS records or remove the CNAME. |
| `KIN-NRS-007` | `TxtRecordTooLong` | **What:** A TXT record payload exceeds the maximum allowed length of 255 bytes.<br>**Why:** This constraint maintains UDP packet size compatibility when the zone is queried via traditional DNS.<br>**Fix:** Break the data into multiple smaller TXT records or host the raw data on IPFS. |
| `KIN-NRS-008` | `InvalidCnameTarget` | **What:** A CNAME target string is empty, too long, or malformed.<br>**Why:** The target must be a valid, resolvable Domain Name.<br>**Fix:** Ensure the CNAME target is a fully-qualified domain name that complies with RFC limits. |
| `KIN-NRS-009` | `InvalidPeerId` | **What:** A PeerId string could not be parsed into a valid Libp2p PeerId.<br>**Why:** The string is either incorrectly encoded (not valid base58/base36) or mathematically invalid.<br>**Fix:** Ensure you copy the exact PeerId generated by the Kinetic node. |
| `KIN-NRS-010` | `InvalidKid` | **What:** A KID string does not start with the required `did:kin:` prefix or is improperly formatted.<br>**Why:** Kinetic Identity Documents must strictly adhere to the DID specification for identity resolution.<br>**Fix:** Prefix the 64-character public key with `did:kin:`. |
| `KIN-NRS-011` | `InvalidIpfsCid` | **What:** An IPFS CID string could not be parsed.<br>**Why:** The string is not a valid IPFS Content Identifier (v0 or v1).<br>**Fix:** Verify the CID using IPFS tools and ensure it is not truncated. |
| `KIN-NRS-001` | `MultipleCnames` | **What:** Multiple CNAME records are assigned to the same label.<br>**Why:** Multiple CNAME records were defined for the exact same label.<br>**Fix:** This violates RFC constraints as a CNAME can only alias to exactly one canonical target. Remove all but one CNAME record for this label. |
| `KIN-NRS-050` | `UpstreamResolveError` | **What:** The node failed to resolve a traditional Web2 DNS query via the upstream UDP proxy.<br>**Why:** The upstream nameserver (e.g. 1.1.1.1) failed to respond or returned an error code.<br>**Fix:** Check the node's upstream DNS configuration and internet connectivity. |
| `KIN-NRS-051` | `DnsRequestFailed` | **What:** The internal DNS server failed to dispatch a request to the resolution engine.<br>**Why:** The internal channel may be blocked or the DNS subsystem may have panicked.<br>**Fix:** Review the daemon logs for panic traces or restart the node. |
| `KIN-NRS-052` | `NrsServerExecutionError` | **What:** An internal execution error occurred in the embedded Trust-DNS server binary.<br>**Why:** The DNS socket may have died, or a critical thread panicked.<br>**Fix:** Review the node's system logs for the underlying failure cause and restart the daemon. |
| `KIN-NRS-053` | `SeedDomainResolutionFailed` | **What:** The node failed to resolve the DNS TXT seed domain for network bootstrapping.<br>**Why:** Without this resolution, the node cannot dynamically discover bootstrap peers.<br>**Fix:** The node will be unable to discover peers automatically until DNS is restored. Check your internet connection. |
| `KIN-NRS-054` | `DnsResolverInitFailed` | **What:** The local node failed to initialize the internal DNS resolver at startup.<br>**Why:** The system's DNS configuration (`/etc/resolv.conf`) may be missing or unreadable.<br>**Fix:** Check the local operating system's network configuration. |
| `KIN-NRS-055` | `DnsLookupFailed` | **What:** A standard DNS lookup failed for a specific external domain.<br>**Why:** The domain may not exist, or the upstream nameserver is currently unreachable.<br>**Fix:** Verify the domain exists and is resolvable via `dig` or `nslookup`. |
| `KIN-NRS-056` | `Web2BridgeResolveFailed` | **What:** The Kinetic Web2 Bridge failed to resolve a Kinetic name into an IP address.<br>**Why:** The name is not registered, has expired, or the Kinetic DHT is temporarily unreachable.<br>**Fix:** Ensure the `.kin` name is valid and that your local node is fully synced with the mesh. |
| `KIN-NRS-057` | `Web2BridgeNoIpsFound` | **What:** The Kinetic Web2 Bridge successfully resolved a name, but no IPs were found in its NRS zone.<br>**Why:** The domain owner has not configured any A or AAAA records in their zone file.<br>**Fix:** This is not a node failure. The domain owner must update their zone configuration to route traffic. |

---

## KIN-NAM - NamesError

**Underlying Type:** `NamesError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-NAM-001` | `NameTooLong` | **What:** The submitted name exceeds the strict 253-character limit or is completely empty.<br>**Why:** The Kinetic naming system strictly inherits RFC 1035 length limits to prevent buffer overflow vulnerabilities.<br>**Fix:** Choose a shorter, concise name to ensure network compatibility. |
| `KIN-NAM-002` | `LabelTooLong` | **What:** A single label (the word between dots) within the name exceeds the 63-character limit.<br>**Why:** The network enforces RFC 1035 label constraints for efficient DNS compatibility and routing.<br>**Fix:** Break the name up using dots or choose a shorter label. |
| `KIN-NAM-003` | `EmptyLabel` | **What:** A single label (the word between dots) is completely empty.<br>**Why:** This usually occurs when consecutive dots are used (e.g., `foo..kin`) or a dot is placed at the start of the string.<br>**Fix:** Ensure there is exactly one dot separating each valid label and no leading dots. |
| `KIN-NAM-XXX` | `"Name contains invalid characters` | **What:** The name contains characters not permitted by the LDH (Letters, Digits, Hyphen) rule.<br>**Why:** To prevent homograph attacks and Unicode confusion, only a highly restricted character set is allowed.<br>**Fix:** Ensure the name strictly contains only lowercase alphanumeric characters and internal hyphens. No emojis or spaces. |
| `KIN-NAM-004` | `InvalidCharacter` | **What:** A prohibited character was used in the payload.<br>**Why:** Strict validation rules prevent injection attacks.<br>**Fix:** Use only valid ASCII/UTF-8 depending on field. |
| `KIN-NAM-005` | `InvalidHyphenPlacement` | **What:** A hyphen was placed at the very start or end of a label (e.g., `-example` or `example-`).<br>**Why:** Hyphens must be strictly internal according to the LDH rule to prevent parsing ambiguities.<br>**Fix:** Ensure all hyphens are strictly surrounded by valid alphanumeric characters. |
| `KIN-NAM-006` | `ReservedName` | **What:** The name is a permanently reserved public utility name (e.g., `localhost`, `test`, `example`).<br>**Why:** These Category 1 names are strictly protected by RFC 2606 to prevent catastrophic network confusion.<br>**Fix:** These names can never be registered on the Kinetic network. Choose a different name. |
| `KIN-NAM-007` | `ProtocolName` | **What:** The name is reserved for critical network protocol functionality (e.g., `seed`, `explorer`, `docs`).<br>**Why:** These Category 2 names are locked by the core protocol to ensure official infrastructure remains secure.<br>**Fix:** These names are locked until Phase 2 governance is activated. Choose a different name. |
| `KIN-NAM-008` | `NotAnApexName` | **What:** An operation was attempted on a subname (e.g., `sub.example.kin`), but the operation strictly requires an apex name.<br>**Why:** The core Kinetic DHT only manages apex names (`example.kin`) to prevent state bloat.<br>**Fix:** Subnames must be managed independently by the apex owner via their local zone file. |

---

## KIN-CFG - ConfigError

**Underlying Type:** `ConfigError`


| Error Code | Enum Variant | Developer Context & Mitigation |
| :--- | :--- | :--- |
| `KIN-CFG-001` | `DirectoryCreationFailed` | **What:** The daemon failed to create the OS-level directory structure for the configuration files.<br>**Why:** The node must ensure its base paths exist before initializing, but the OS rejected the system call.<br>**Fix:** Check the file permissions for the user running the daemon and ensure the disk is not read-only. |
| `KIN-CFG-002` | `SerializationFailed` | **What:** The node attempted to write the configuration to disk, but the TOML serialization engine failed.<br>**Why:** This usually indicates a critical structural flaw in the default configuration structs or an unsupported data type.<br>**Fix:** This is an internal node error; report this bug to the Kinetic developers on GitHub. |
| `KIN-CFG-003` | `WriteFailed` | **What:** The local node failed to write a value to the database engine.<br>**Why:** The operating system rejected the write syscall.<br>**Fix:** Ensure the disk is not completely full and the daemon has write permissions. |
| `KIN-CFG-004` | `ParseFailed` | **What:** The `kinetic.toml` file exists but contains invalid TOML syntax or structural errors.<br>**Why:** The node refuses to start with an invalid config rather than failing-open with missing or default parameters.<br>**Fix:** Review the accompanying error string to find the syntax error or missing field in your config file. |
| `KIN-CFG-005` | `ReadFailed` | **What:** The local node failed to read a value from the database engine.<br>**Why:** This could indicate underlying disk issues or unreadable sectors.<br>**Fix:** Check the host filesystem health and disk space. |
| `KIN-CFG-006` | `TcpPortCollision` | **What:** The daemon detected that two or more internal services are trying to bind to the same TCP port.<br>**Why:** A misconfigured node will fail to bind its sockets at startup if ports conflict, breaking routing.<br>**Fix:** Update `kinetic.toml` to ensure all TCP ports (api, proxy, p2p, backend) are entirely unique. |
| `KIN-CFG-007` | `UdpPortCollision` | **What:** The daemon detected that two or more internal services are trying to bind to the same UDP port.<br>**Why:** A misconfigured node will fail to bind its sockets at startup if ports conflict, dropping packets.<br>**Fix:** Update `kinetic.toml` to ensure all UDP ports (nrs, quic) are entirely unique. |
| `KIN-CFG-008` | `BackendPortCollision` | **What:** The `backend_port` in the configuration is set to a port already used by an internal daemon service.<br>**Why:** This must be strictly blocked to prevent infinite SSRF loops if the proxy attempts to route traffic back into its own API.<br>**Fix:** Assign a unique, unused port to your upstream backend application in `kinetic.toml`. |
| `KIN-CFG-009` | `BackendPortSsrfRisk` | **What:** A secondary fatal warning paired with `KIN-CFG-008` port collisions.<br>**Why:** Leaving this misconfigured exposes the node to infinite routing loops and localized SSRF proxy exploits.<br>**Fix:** Resolve the port collision immediately before starting the node. |
| `KIN-CFG-010` | `InvalidApiUpdate` | **What:** A REST API request attempted to update the daemon configuration with invalid data.<br>**Why:** The submitted JSON payload failed schema validation (e.g., trying to set a port to a negative number).<br>**Fix:** Review the accompanying API error response to correct your configuration payload. |

---