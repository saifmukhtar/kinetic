# Kinetic Error Handbook

This document serves as the official reference for the Kinetic protocol's error codes (`KIN-*`). The daemon and API use these stable error codes to communicate problems to clients in an RFC 7807-compatible JSON format.

Below is the complete taxonomy of errors you might encounter when interacting with the Kinetic API, along with their HTTP status mappings and user-facing explanations.

---

## Name Resolution Errors (`KIN-RES-*`)
Errors that occur when attempting to resolve a `.kin` domain via the DHT.

| Error Code | HTTP Status | Meaning | Developer Detail |
| :--- | :--- | :--- | :--- |
| **KIN-RES-001** | `503 Service Unavailable` | **Offline**: You appear to be offline. The node cannot connect to the P2P network to resolve names. | Node has no connected DHT peers. |
| **KIN-RES-002** | `404 Not Found` | **Not Found**: The domain is not registered on the Kinetic network. | Lookups failed after checking multiple peers. |
| **KIN-RES-003** | `422 Unprocessable Entity` | **Cryptographic Verification Failed**: The name was found, but the record has an invalid cryptographic proof, indicating potential tampering. | The VDF proof embedded in the record was rejected. |
| **KIN-RES-004** | `410 Gone` | **Registration Expired**: The name's registration has expired. The owner needs to renew it. | Record age in drand rounds exceeds the maximum validity window. |
| **KIN-RES-005** | `504 Gateway Timeout` | **Resolution Timeout**: The network took too long to respond. Please try again. | Query exceeded the internal DHT timeout threshold. |
| **KIN-RES-006** | `500 Internal Server Error` | **Internal Resolution Error**: An internal network error occurred during resolution. | Unhandled internal logic panic or storage failure. |

---

## Name Publishing Errors (`KIN-PUB-*`)
Errors that occur when attempting to write a new or updated record to the DHT.

| Error Code | HTTP Status | Meaning | Developer Detail |
| :--- | :--- | :--- | :--- |
| **KIN-PUB-001** | `503 Service Unavailable` | **Offline**: Cannot publish because the node is offline. | No active DHT peers available for `PUT`. |
| **KIN-PUB-002** | `400 Bad Request` | **Invalid VDF Proof**: The computational proof of work attached to the publish request is invalid and was rejected. | The `chiavdf` verifier failed. |
| **KIN-PUB-003** | `409 Conflict` | **Name Already Owned**: The requested `.kin` name is already registered under a different public key. | Ed25519 signature mismatch on existing valid record. |
| **KIN-PUB-004** | `503 Service Unavailable` | **Publish Failed**: The network rejected all DHT publish attempts. | Every single `PUT` request failed across the routing table. |
| **KIN-PUB-005** | `500 Internal Server Error` | **Internal Publish Error**: An unexpected internal error occurred during the publish flow. | Storage or configuration error prevented publishing. |

---

## Registration Lifecycle Errors (`KIN-REG-*`)
Errors that occur during the end-to-end domain registration (Commit/Reveal) process.

| Error Code | HTTP Status | Meaning | Developer Detail |
| :--- | :--- | :--- | :--- |
| **KIN-REG-001** | `400 Bad Request` | **Invalid Name**: Name contains invalid characters. Use only lowercase letters, digits, and hyphens. | Failed regex/UTF-8 validation checks. |
| **KIN-REG-002** | `500 Internal Server Error` | **VDF Computation Failed**: The heavy mathematical computation failed locally. | The underlying `chiavdf` engine panicked or encountered an error. |
| **KIN-REG-003** | `422 Unprocessable Entity` | **Commitment Mismatch**: The registration data is inconsistent with the previously broadcast hash. | The Phase 2 Reveal hash did not match the Phase 1 Commit hash. |
| **KIN-REG-004** | `409 Conflict` | **Already Owned**: The name is already registered by someone else. | Front-running defense triggered. |
| **KIN-REG-005** | `409 Conflict` | **Registration In Progress**: A registration is already actively computing for this name. | Only one VDF task per name is permitted concurrently. |
| **KIN-REG-006** | `422 Unprocessable Entity` | **Registration Rejected**: The network actively rejected the registration attempt. | See `reject_reason` in error details. |
| **KIN-REG-007** | `500 Internal Server Error` | **Internal Registration Error**: An unexpected issue occurred during registration. | Catch-all for IO or state errors during the flow. |

---

## Governance Errors (`KIN-GOV-*`)
Errors related to on-chain OTA updates and Council voting logic.

| Error Code | HTTP Status | Meaning | Developer Detail |
| :--- | :--- | :--- | :--- |
| **KIN-GOV-001** | `500 Internal Server Error` | **Missing Root Key**: Fatal configuration error. `ROOT_PUBLIC_KEY_HEX` is not set. | Node missing Founder Key config. |
| **KIN-GOV-002** | `500 Internal Server Error` | **Missing Guard Key**: Fatal configuration error. `GUARD_PUBLIC_KEY_HEX` is not set. | Node missing Veto Key config. |
| **KIN-GOV-003** | `400 Bad Request` | **Key Length Mismatch**: A supplied public key is not exactly 32 bytes. | Malformed Ed25519 input. |
| **KIN-GOV-004** | `409 Conflict` | **Stale Proposal**: The governance action is too old and was rejected to prevent replay attacks. | Timestamp outside the allowable replay window. |
| **KIN-GOV-005** | `409 Conflict` | **Timelock Not Expired**: The governance action is still in its mandatory waiting period. | Action attempted before `unlock_time`. |
| **KIN-GOV-006** | `409 Conflict` | **OTA Timelock Not Expired**: The 24-hour waiting period for binary replacement has not elapsed. | Network safety delay active. |
| **KIN-GOV-007** | `409 Conflict` | **Not Pending Or Vetoed**: The target hash is not in a pending state or was actively vetoed by the Guard. | Action aborted or non-existent. |
| **KIN-GOV-008** | `400 Bad Request` | **Council Size Mismatch**: The proposer claimed an artificially low denominator to bypass the 69% threshold. | Invalid signature pool structure. |
| **KIN-GOV-009** | `401 Unauthorized` | **Invalid Guard Signature**: The veto signature provided by the Guard key is invalid. | Crypto verification failed. |
| **KIN-GOV-010** | `403 Forbidden` | **Emergency Reset Vetoed**: The Emergency Reset has been permanently vetoed. | Reset action aborted. |
| **KIN-GOV-011** | `403 Forbidden` | **Emergency Reset Requires Root**: The reset action lacks a valid Founder signature. | Unauthorized privileged action. |
| **KIN-GOV-012** | `403 Forbidden` | **Emergency Reset Requires Guard**: The reset action (without override) lacks a valid Guard signature. | Unauthorized privileged action. |
| **KIN-GOV-013** | `403 Forbidden` | **Rotate Requires Guard**: A Root key rotation requires a Guard co-signature. | Unauthorized privileged action. |
| **KIN-GOV-014** | `501 Not Implemented` | **Unhandled Threshold Math**: The requested threshold math is not supported by the council voting logic. | Logic bug or unknown feature flag. |
| **KIN-GOV-015** | `403 Forbidden` | **Empty Council**: The council is empty; actions must be performed by the Root Key. | Phase 1 fallback triggered on Phase 2 node. |
| **KIN-GOV-016** | `401 Unauthorized` | **Insufficient Signatures**: The action does not have the required 69% valid supermajority. | Threshold voting failed. |

---

## Network Client & Peer Errors (`KIN-NET-*`)
Errors originating from the libp2p transport and Kademlia DHT layers.

| Error Code | HTTP Status | Meaning | Developer Detail |
| :--- | :--- | :--- | :--- |
| **KIN-NET-001** | `504 Gateway Timeout` | **Request Timed Out**: A network request exceeded its deadline. | Local or remote timeout triggered. |
| **KIN-NET-002** | `503 Service Unavailable` | **Node is Offline**: Node has no reachable peers. | Swarm disconnected. |
| **KIN-NET-003** | `503 Service Unavailable` | **Routing Table Empty**: The Kademlia routing table contains no known peers. | DHT bootstrap failed or no peers discovered. |
| **KIN-NET-004** | `500 Internal Server Error` | **Internal Channel Closed**: Communication between the API thread and the P2P loop broke down. | Async task panic or drop. |
| **KIN-NET-005** | `504 Gateway Timeout` | **Stream Dropped**: The remote peer closed the connection before fully responding. | Premature EOF. |
| **KIN-NET-006** | `501 Not Implemented` | **Unsupported Protocol**: Remote peer does not speak the requested Kinetic protocol version. | Protocol mismatch during negotiation. |
| **KIN-NET-007** | `502 Bad Gateway` | **Gossipsub Error**: Failed to publish or subscribe to a GossipSub topic. | Network propagation failed. |
| **KIN-NET-008** | `500 Internal Server Error` | **Store Error**: The local Kademlia record store threw an error. | Memory/DB access failure. |
| **KIN-NET-009** | `500 Internal Server Error` | **Other Network Error**: A miscellaneous transport error. | Uncategorized libp2p error. |

---

## Storage Engine Errors (`KIN-STO-*`)
Errors emitted by the embedded `sled` database engine.

| Error Code | HTTP Status | Meaning | Developer Detail |
| :--- | :--- | :--- | :--- |
| **KIN-STO-001** | `423 Locked` | **Database Locked**: Another instance of the Kinetic daemon is already running. | Process lock file collision. |
| **KIN-STO-002** | `500 Internal Server Error` | **Storage Corruption**: The local database structure has been corrupted. | Automatic backup & reset triggered. |
| **KIN-STO-003** | `500 Internal Server Error` | **Operation Failed**: A read/write operation failed at the engine level. | Disk IO or thread panic inside Sled. |

---

## OTA Auto-Updater Errors (`KIN-OTA-*`)
Errors related to the Over-The-Air binary hot-swapping mechanism.

| Error Code | HTTP Status | Meaning | Developer Detail |
| :--- | :--- | :--- | :--- |
| **KIN-OTA-001** | `400 Bad Request` | **No Mirrors Provided**: Update failed because no download URLs were provided by the council. | Empty mirror array in `SignedGovernanceMessage`. |
| **KIN-OTA-002** | `502 Bad Gateway` | **HTTP Status Error**: Update failed due to a server error (HTTP code). | Target HTTP server returned 4xx/5xx. |
| **KIN-OTA-003** | `502 Bad Gateway` | **Network Error**: Update failed due to a transport error during download. | TCP/TLS failure. |
| **KIN-OTA-004** | `502 Bad Gateway` | **Reqwest Error**: Internal HTTP client failed to initialize or execute. | `reqwest` crate error. |
| **KIN-OTA-005** | `500 Internal Server Error` | **I/O Error**: Issue writing the new binary version to disk. | File permission or space issue. |
| **KIN-OTA-006** | `500 Internal Server Error` | **Self Replace Error**: The node failed to seamlessly replace itself with the updated binary. | `self_replace` crate failure. |
| **KIN-OTA-007** | `400 Bad Request` | **Hash Mismatch**: Downloaded software did not match the expected cryptographic hash. | Download corruption or supply chain attack. |
| **KIN-OTA-008** | `500 Internal Server Error` | **Spawn Failed**: Update succeeded, but the node failed to restart automatically. | `Command::new` failure. |

---

## Verifiable Delay Function (VDF) Errors (`KIN-VDF-*`)
Errors occurring during intense CPU math tasks and Class Group cryptography.

| Error Code | HTTP Status | Meaning | Developer Detail |
| :--- | :--- | :--- | :--- |
| **KIN-VDF-001** | `503 Service Unavailable` | **Lock File Error**: Failed to create the VDF lock file to serialize heavy tasks. | Permission/IO error in `~/.kinetic`. |
| **KIN-VDF-002** | `503 Service Unavailable` | **Lock Acquire Error**: Failed to acquire the VDF lock due to timeout or OS failure. | Another thread is hogging the CPU for too long. |
| **KIN-VDF-003** | `500 Internal Server Error` | **Discriminant Error**: Failed to cryptographically map the network challenge to a valid prime discriminant. | Class group initialization error. |
| **KIN-VDF-004** | `500 Internal Server Error` | **Proof Generation Error**: The chiavdf prover threw an internal error and failed. | Math panic inside C++ bindings. |
| **KIN-VDF-005** | `501 Not Implemented` | **Unsupported Platform**: VDF operation is unsupported on this OS/Architecture. | chiavdf binary missing for architecture. |

---

## Drand Quicknet Errors (`KIN-DRA-*`)
Errors occurring during Drand randomness beacon fetches and cache operations.

| Error Code | HTTP Status | Meaning | Developer Detail |
| :--- | :--- | :--- | :--- |
| **KIN-DRA-001** | `502 Bad Gateway` | **All Endpoints Failed**: All configured Drand endpoints returned errors or timed out. | Could not reach any healthy nodes. |
| **KIN-DRA-002** | `502 Bad Gateway` | **Network Error**: A network-level error occurred while fetching Drand pulse. | DNS failure or connection refused. |
| **KIN-DRA-003** | `* Upstream Error` | **HTTP Status Error**: A Drand endpoint returned a non-2xx HTTP status. | The specific status is dynamic. |
| **KIN-DRA-004** | `404 Not Found` | **No Cached Pulse**: No pulse was found in the local cache, and the network is unavailable. | Offline cache miss. |
| **KIN-DRA-005** | `500 Internal Server Error` | **Serialization Error**: JSON (de)serialization of the Drand pulse failed. | Payload format changed or corrupted. |
| **KIN-DRA-006** | `500 Internal Server Error` | **Storage Error**: A local storage engine error occurred while reading or writing the pulse cache. | Engine read/write failed. |
| **KIN-DRA-007** | `502 Bad Gateway` | **Reqwest Error**: An HTTP client error occurred. | `reqwest` internal error. |
| **KIN-DRA-008** | `422 Unprocessable Entity` | **Invalid Drand Signature**: The BLS threshold signature was mathematically invalid. | Possible tampering or corrupted beacon. |

---

## DNS Validation Errors (`KIN-DNS-*`)
Errors occurring when parsing or validating `.kin` DNS zone files and records.

| Error Code | HTTP Status | Meaning | Developer Detail |
| :--- | :--- | :--- | :--- |
| **KIN-DNS-001** | `400 Bad Request` | **Nested Too Deeply**: The JSON payload has too many nested structures. | JSON recursion depth exceeded 10. |
| **KIN-DNS-002** | `400 Bad Request` | **Parse Error**: The payload is not valid JSON or does not match the DnsZone schema. | `serde_json` error. |
| **KIN-DNS-003** | `400 Bad Request` | **Too Many Records**: The zone contains more than the maximum 50 allowed records. | Anti-bloat limit enforcement. |
| **KIN-DNS-004** | `400 Bad Request` | **Invalid Label Length**: A label is empty or longer than 63 characters. | Follows DNS RFC limits. |
| **KIN-DNS-005** | `400 Bad Request` | **Invalid Label Characters**: A label contains non-alphanumeric characters or starts/ends with a hyphen. | Follows DNS RFC limits. |
| **KIN-DNS-006** | `400 Bad Request` | **Invalid CNAME Configuration**: A CNAME record was provided alongside other records for the same label. | RFC violation. |
| **KIN-DNS-007** | `400 Bad Request` | **TXT Record Too Long**: A TXT record exceeds the maximum allowed length of 255 bytes. | Anti-bloat limit enforcement. |
| **KIN-DNS-008** | `400 Bad Request` | **Invalid CNAME Target**: A CNAME target is empty or longer than 253 characters. | Follows DNS RFC limits. |
| **KIN-DNS-009** | `400 Bad Request` | **Invalid PeerId**: The string could not be parsed into a valid libp2p PeerId. | Invalid base58 encoding. |
| **KIN-DNS-010** | `400 Bad Request` | **Invalid KID**: The string does not start with the required `did:kin:` prefix. | DID syntax validation. |

---

## Identity & Seed Errors (`KIN-IDN-*`)
Errors related to node identity keypairs and mnemonic seed phrases.

| Error Code | HTTP Status | Meaning | Developer Detail |
| :--- | :--- | :--- | :--- |
| **KIN-IDN-001** | `500 Internal Server Error` | **I/O Error**: An OS-level error occurred reading or writing the identity file. | File permissions or disk issue. |
| **KIN-IDN-002** | `500 Internal Server Error` | **Corrupted Identity File**: The loaded identity file does not contain exactly 32 bytes. | Truncated or modified key file. |
| **KIN-IDN-003** | `404 Not Found` | **Identity Not Found**: The local identity file could not be found. | `kinetic-cli seed init` has not been run. |
| **KIN-IDN-004** | `400 Bad Request` | **Invalid Seed Phrase**: The provided seed phrase is not a valid BIP-39 mnemonic. | Typo or invalid dictionary word. |
