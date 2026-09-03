//! DHT record rejection, resolution, publish, and registration error types.
//!
//! Defines three primary error enums used in the two-phase name registration
//! protocol (commit → reveal) and the DHT name resolution flow:
//!
//! - [`RecordRejectReason`] — fine-grained reasons a DHT `PUT` was rejected by
//!   the local `KineticRecordStore`.
//! - [`ResolutionError`] — errors during DHT name lookup (`KIN-QRY-NNN`).
//! - [`PublishError`] — errors when pushing records to the DHT (`KIN-PUB-NNN`).
//! - [`RegistrationError`] — errors in the full name registration flow (`KIN-REG-NNN`).
//!
//! All three rich error types expose `code()`, `error_type_uri()`, `is_retryable()`,
//! `severity()`, `user_message()`, and `details()` to satisfy the Kinetic error taxonomy.
use super::Severity;
use super::vdf::VdfRejectReason;
use thiserror::Error;

/// Why a DHT record was rejected by the local store.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum RecordRejectReason {
    /// The record's cryptographic signature did not verify against the public key.
    /// This happens if the payload was tampered with, or signed with the wrong key.
    /// Verify that the record is generated using the authorized identity key (ML-DSA-65) or transport key (Ed25519).
    #[error("invalid signature")]
    InvalidSignature,
    /// The embedded VDF proof failed cryptographic verification.
    /// A peer attempted to submit a forged or malformed proof of time.
    /// Ensure your local VDF engine is generating valid proofs.
    #[error("VDF proof invalid")]
    InvalidVdf,
    /// The registration epoch has passed and the record is no longer valid.
    /// The current drand round has advanced past the record's expiry window.
    /// The apex owner must generate a fresh heartbeat to maintain registration.
    #[error("registration has expired")]
    Expired,
    /// The name is already owned by a different public key.
    /// The DHT already contains a valid, stronger commitment for this name from another user.
    /// You must choose a different, unregistered name.
    #[error("name already owned by a different key")]
    AlreadyOwned,

    /// The VDF iteration count is below the minimum required for this name and kyn.
    /// The submitter did not compute the VDF for a long enough time.
    /// Ensure the client enforces the global dynamic difficulty floor.
    #[error("insufficient VDF iterations to claim ownership")]
    InsufficientIterations,
    /// The record lost an XOR-distance tie-break to a competing record.
    /// Two valid commitments were submitted for the same name at the exact same kyn.
    /// The network resolved the tie cryptographically. Try registering again in the next epoch.
    #[error("lost XOR tie-break to stronger record")]
    TieBroken,
    /// The revealed data's hash does not match the stored commitment.
    /// A peer tried to reveal a payload that differs from the hash they previously committed.
    /// The publish flow requires the reveal payload to perfectly hash to the commitment.
    #[error("commitment mismatch")]
    CommitmentMismatch,
    /// The `drand_signature` field contains non-hex characters.
    /// All signature proofs must be strictly hex-encoded strings.
    #[error("drand_signature contains invalid hex")]
    InvalidDrandHex,
    /// The public key bytes could not be parsed as a valid cryptographic key.
    /// The key is either the wrong length or cryptographically invalid (e.g. malformed Ed25519 or ML-DSA-65 key).
    #[error("public key bytes are malformed")]
    InvalidPublicKey,
    /// The signature bytes are the wrong length or otherwise malformed.
    /// The signature must match the expected byte length for the record's underlying algorithm.
    #[error("signature bytes are malformed")]
    MalformedSignature,
}

// ─── ResolutionError ──────────────────────────────────────────────────────────

/// Errors during DHT name resolution. Rich developer context, NOT serialized over wire.
/// Convert to `ApiError` at the HTTP/FFI boundary.
#[derive(Error, Debug)]
pub enum ResolutionError {
    /// The local node has no connected peers and cannot reach the DHT.
    /// The P2P swarm must be connected to at least one bootstrap or regular peer to resolve names.
    /// Check your internet connection or verify that bootstrap nodes are online.
    #[error("Node is offline — no peers connected")]
    Offline,
    /// The name was not found after querying the given number of peers.
    /// The DHT was successfully traversed, but the requested `.kin` name has no active records.
    /// The name may be unregistered, expired, or misspelled.
    #[error("'{name}' not found after querying {peers_queried} peers")]
    NotFound {
        /// The `.kin` name that was queried.
        name: String,
        /// Number of DHT peers that were contacted.
        peers_queried: usize,
    },
    /// The name was found but one or more of the returned records failed VDF verification.
    /// A peer returned a payload with a cryptographically invalid proof of time.
    /// The malicious records were discarded. If all records fail, the name cannot be safely resolved.
    #[error("'{name}' found but {count} record(s) failed VDF verification")]
    VdfVerificationFailed {
        /// The `.kin` name that was queried.
        name: String,
        /// Number of records that failed verification.
        count: usize,
    },
    /// The name's registration has passed its validity window.
    /// The network time (drand kyn) has advanced past the expiration limit of the NameRecord.
    /// The owner must renew the registration by publishing a fresh heartbeat.
    #[error("'{name}' registration has expired ({age} rounds old)")]
    Expired {
        /// The `.kin` name that was queried.
        name: String,
        /// Age of the record in drand rounds.
        age: u64,
    },
    /// The resolution attempt timed out before a result was returned.
    /// The DHT query took longer than the configured strict timeout bounds.
    /// The network may be heavily congested or the user's connection is unstable. Retry the query.
    #[error("Resolution timed out after {elapsed_ms}ms ({peers_queried} peers queried)")]
    Timeout {
        /// The `.kin` name that was queried.
        name: String,
        /// Wall-clock time elapsed during the query in milliseconds.
        elapsed_ms: u64,
        /// Number of DHT peers that were contacted before the timeout.
        peers_queried: usize,
    },
    /// An unexpected internal error occurred during resolution.
    /// A localized crash, parse failure, or channel panic occurred inside the Kademlia handler.
    /// Check the daemon logs for stack traces and ensure the database isn't corrupted.
    #[error("Internal error: {message}")]
    Internal {
        /// Developer-facing description of what went wrong.
        message: String,
        /// Optional chain of underlying error causes.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    /// The record's signature failed cryptographic verification (spoofed/tampered).
    /// A peer attempted to route a malicious record posing as the apex owner.
    /// The record was safely dropped.
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),
}

impl ResolutionError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Offline => "KIN-QRY-001",
            Self::NotFound { .. } => "KIN-QRY-002",
            Self::VdfVerificationFailed { .. } => "KIN-QRY-003",
            Self::Expired { .. } => "KIN-QRY-004",
            Self::Timeout { .. } => "KIN-QRY-005",
            Self::Internal { .. } => "KIN-QRY-006",
            Self::SignatureVerificationFailed(_) => "KIN-QRY-011",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Offline | Self::Timeout { .. })
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::Offline => Severity::Warning,
            Self::NotFound { .. } => Severity::Info,
            Self::VdfVerificationFailed { .. } => Severity::Error,
            Self::Expired { .. } => Severity::Info,
            Self::Timeout { .. } => Severity::Warning,
            Self::Internal { .. } => Severity::Error,
            Self::SignatureVerificationFailed(_) => Severity::Error,
        }
    }

    /// Clean user-facing message with no developer details.
    pub fn user_message(&self) -> String {
        match self {
            Self::Offline => {
                "You appear to be offline. Check your internet connection.".to_string()
            }
            Self::NotFound { name, .. } => {
                format!("'{}' is not registered on the Kinetic network.", name)
            }
            Self::VdfVerificationFailed { name, .. } => format!(
                "'{}' has an invalid cryptographic proof. This record may have been tampered with.",
                name
            ),
            Self::Expired { name, .. } => format!(
                "'{}' registration has expired. The owner needs to renew it.",
                name
            ),
            Self::Timeout { name, .. } => format!(
                "The network took too long to respond for '{}'. Please try again.",
                name
            ),
            Self::Internal { .. } => {
                "An internal network error occurred. Please try again.".to_string()
            }
            Self::SignatureVerificationFailed(_) => {
                "The network returned a spoofed or tampered record. Query rejected for your safety."
                    .to_string()
            }
        }
    }

    /// Structured developer-facing details for ApiError.details.
    pub fn details(&self) -> serde_json::Value {
        match self {
            Self::NotFound { peers_queried, .. } => {
                serde_json::json!({ "peers_queried": peers_queried })
            }
            Self::Timeout {
                elapsed_ms,
                peers_queried,
                ..
            } => serde_json::json!({ "elapsed_ms": elapsed_ms, "peers_queried": peers_queried }),
            Self::VdfVerificationFailed { count, .. } => {
                serde_json::json!({ "failed_record_count": count })
            }
            Self::Expired { age, .. } => serde_json::json!({ "age_rounds": age }),
            _ => serde_json::Value::Null,
        }
    }
}

// ─── PublishError ─────────────────────────────────────────────────────────────

/// Errors when publishing records to the DHT.
#[derive(Error, Debug)]
pub enum PublishError {
    /// The local node has no connected peers and cannot write to the DHT.
    /// The publish operation requires a live P2P mesh to broadcast the record.
    /// Check your internet connection or verify that bootstrap nodes are online.
    #[error("Node is offline — cannot publish to the DHT")]
    Offline,
    /// The VDF proof attached to the record failed verification.
    /// You attempted to publish a record with a corrupted, forged, or insufficient proof of time.
    /// Ensure your node successfully generates a valid proof before publishing.
    #[error("VDF proof is invalid: {0}")]
    InvalidProof(#[from] VdfRejectReason),
    /// The name is already owned by a different identity key (ML-DSA-65).
    /// Another user has a valid registration for this name in the DHT.
    /// You must choose a different, unregistered name.
    #[error("'{name}' is already owned by a different key")]
    AlreadyOwned {
        /// The `.kin` name that is already registered.
        name: String,
    },
    /// Every DHT `PUT` attempt for this record failed.
    /// The network is heavily congested or peers are refusing to store the record.
    /// Wait a few minutes and try publishing again.
    #[error("All {count} DHT put operations failed")]
    AllFailed {
        /// Number of failed PUT operations.
        count: usize,
    },
    /// The record was rejected by the store (e.g. invalid signature, stale).
    /// The DHT nodes validated the payload and found it cryptographically or temporally invalid.
    /// Ensure your local clock is synced and your signature keys are correct.
    #[error("Rejected by the network: {0}")]
    Rejected(String),
    /// An unexpected internal error occurred during the publish flow.
    /// A localized crash, parse failure, or channel panic occurred inside the Kademlia handler.
    /// Check the daemon logs for stack traces and ensure the database isn't corrupted.
    #[error("Internal error: {message}")]
    Internal {
        /// Developer-facing description of what went wrong.
        message: String,
        /// Optional chain of underlying error causes.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    /// The network did not reach the required replication quorum for the zone.
    /// A required minimum number of DHT peers must confirm they stored the record.
    /// Wait and retry publishing later.
    #[error("Quorum failed for {0}: only {1}/5 nodes confirmed storage")]
    QuorumFailed(String, usize),
    /// The quorum verification check failed due to a network error.
    /// The node lost connection to the DHT while verifying the quorum.
    /// Retry the publish operation.
    #[error("Quorum check failed for {0}: {1}")]
    QuorumCheckError(String, String),
    /// A lower-level network error occurred while publishing the zone record.
    /// This could be a timeout or stream failure.
    /// Retry the publish operation.
    #[error("Failed to publish zone record: {0}")]
    ZonePublishFailed(String),
    /// The network did not reach the required replication quorum for the commitment.
    /// At least 5 peers must acknowledge storing the commitment to ensure it isn't lost during the reveal window.
    /// Wait a few seconds and try publishing the commitment again.
    #[error("Quorum failed for commitment of {0}: only {1}/5 nodes confirmed storage")]
    CommitmentQuorumFailed(String, usize),
    /// The quorum verification check failed for the commitment due to a network error.
    /// The node lost its connection to the DHT swarm while waiting for peer acknowledgements.
    /// Check your internet connection and retry the commitment.
    #[error("Quorum check failed for commitment of {0}: {1}")]
    CommitmentQuorumCheckError(String, String),
    /// Failed to publish the commitment to the DHT.
    /// An underlying libp2p Kademlia error occurred while attempting to put the record.
    /// Check node connectivity and retry.
    #[error("Failed to publish Commitment to DHT: {0}")]
    CommitmentPublishFailed(String),
    /// The local reveal could not be found to verify the AuthorizedKid locally before broadcast.
    /// The local node doesn't have the active name reveal cached, meaning it cannot pre-validate the KID.
    /// The network will likely drop this payload. Ensure you own the name and it is fully synced locally.
    #[error("Could not find local reveal for name {0} to verify AuthorizedKid. Forwarding to DHT anyway, but it may be rejected by the network.")]
    MissingLocalRevealForKid(String),
    /// The local reveal could not be found to verify the AuthorizedManifest locally before broadcast.
    /// The local node cannot verify the manifest signature locally because it doesn't have the parent reveal.
    /// The payload will be forwarded, but might be rejected by peers. Fully sync the node before publishing.
    #[error("Could not find local reveal for name {0} to verify AuthorizedManifest. Forwarding to DHT anyway.")]
    MissingLocalRevealForManifest(String),
    /// The zone payload failed to serialize into JSON.
    /// The zone struct contains invalid characters, cyclical references, or exceeds nesting limits.
    /// Verify your NrsZone struct data and ensure all fields are standard strings/numbers.
    #[error("Failed to serialize zone data: {0}")]
    ZoneSerializationFailed(String),
    /// Failed to broadcast the dynamic HostRoutingRecord to the DHT.
    /// A libp2p timeout or swarm error occurred while propagating the host IP/PeerID.
    /// The host may not be fully reachable on the network. Check port forwarding.
    #[error("Failed to broadcast dynamic HostRoutingRecord to DHT: {0}")]
    HostRoutingRecordPublishFailed(String),
    /// Failed to publish the cryptographic KID document to the DHT.
    /// A lower-level network error or DHT timeout blocked the put request.
    /// Retry the publish operation.
    #[error("Failed to publish KID to DHT: {0}")]
    KidPublishFailed(String),
    /// Failed to publish the delegated Manifest to the DHT.
    /// The network timed out or rejected the payload during the put attempt.
    /// Retry the publish operation.
    #[error("Failed to publish Manifest to DHT: {0}")]
    ManifestPublishFailed(String),
}

impl PublishError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Offline => "KIN-PUB-001",
            Self::InvalidProof(_) => "KIN-PUB-002",
            Self::AlreadyOwned { .. } => "KIN-PUB-003",
            Self::AllFailed { .. } => "KIN-PUB-004",
            Self::Rejected(_) => "KIN-PUB-005",
            Self::Internal { .. } => "KIN-PUB-006",
            Self::QuorumFailed(..) => "KIN-PUB-007",
            Self::QuorumCheckError(..) => "KIN-PUB-008",
            Self::ZonePublishFailed(_) => "KIN-PUB-009",
            Self::CommitmentQuorumFailed(..) => "KIN-PUB-010",
            Self::CommitmentQuorumCheckError(..) => "KIN-PUB-011",
            Self::CommitmentPublishFailed(_) => "KIN-PUB-012",
            Self::MissingLocalRevealForKid(_) => "KIN-PUB-013",
            Self::MissingLocalRevealForManifest(_) => "KIN-PUB-014",
            Self::ZoneSerializationFailed(_) => "KIN-PUB-015",
            Self::HostRoutingRecordPublishFailed(_) => "KIN-PUB-016",
            Self::KidPublishFailed(_) => "KIN-PUB-017",
            Self::ManifestPublishFailed(_) => "KIN-PUB-018",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Offline | Self::AllFailed { .. })
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::Offline => Severity::Warning,
            Self::InvalidProof(_) => Severity::Error,
            Self::AlreadyOwned { .. } => Severity::Info,
            Self::AllFailed { .. } => Severity::Warning,
            Self::Rejected(_) => Severity::Warning,
            Self::Internal { .. } => Severity::Error,
            Self::QuorumFailed(..) => Severity::Warning,
            Self::QuorumCheckError(..) => Severity::Warning,
            Self::ZonePublishFailed(_) => Severity::Error,
            Self::CommitmentQuorumFailed(..) => Severity::Warning,
            Self::CommitmentQuorumCheckError(..) => Severity::Warning,
            Self::CommitmentPublishFailed(_) => Severity::Error,
            Self::MissingLocalRevealForKid(_) => Severity::Warning,
            Self::MissingLocalRevealForManifest(_) => Severity::Warning,
            Self::ZoneSerializationFailed(_) => Severity::Error,
            Self::HostRoutingRecordPublishFailed(_) => Severity::Error,
            Self::KidPublishFailed(_) => Severity::Error,
            Self::ManifestPublishFailed(_) => Severity::Error,
        }
    }

    /// Clean user-facing message with no developer details.
    pub fn user_message(&self) -> String {
        match self {
            Self::Offline => "You appear to be offline. Cannot publish to the network.".to_string(),
            Self::InvalidProof(_) => "The VDF proof is invalid and was rejected.".to_string(),
            Self::AlreadyOwned { name } => {
                format!("'{}' is already registered under a different key.", name)
            }
            Self::AllFailed { .. } => {
                "The network rejected all publish attempts. Please try again.".to_string()
            }
            Self::Rejected(reason) => format!("Publish rejected: {}", reason),
            Self::Internal { .. } => "An internal error occurred during publishing.".to_string(),
            _ => self.to_string(),
        }
    }

    /// Structured developer-facing details for [`ApiError`](crate::api_error::ApiError).
    pub fn details(&self) -> serde_json::Value {
        match self {
            Self::AllFailed { count } => serde_json::json!({ "failed_count": count }),
            Self::InvalidProof(r) => serde_json::json!({ "reason": r.to_string() }),
            _ => serde_json::Value::Null,
        }
    }
}

// ─── RegistrationError ────────────────────────────────────────────────────────

/// Errors during .kin name registration flow.
#[derive(Error, Debug)]
pub enum RegistrationError {
    /// The requested name contains characters not allowed by the Kinetic naming rules.
    /// Apex names must be alphanumeric, lowercase, and cannot contain special characters.
    /// Correct the name string and try your registration again.
    #[error("Name '{name}' contains invalid characters")]
    InvalidName {
        /// The invalid name that was submitted.
        name: String,
    },
    /// The VDF computation step failed (e.g., the underlying engine returned an error or crashed).
    /// The CPU could not complete the required time-delay proof for the registration.
    /// Check system logs, ensure the VDF binary is executable, and try again.
    #[error("VDF computation failed: {0}")]
    VdfFailed(#[from] VdfRejectReason),
    /// The revealed data's hash did not match the previously published commitment.
    /// This happens if the registration parameters were modified between the commit and reveal phases.
    /// Restart the registration process from the beginning without altering parameters.
    #[error("Commitment mismatch — reveal data does not match commitment")]
    CommitmentMismatch,
    /// The name was claimed by a different key before this registration completed.
    /// Another user successfully completed their PoW and revealed before your node finished.
    /// You must choose a different, unregistered name or compute a longer PoW to steal it.
    #[error("'{name}' is already owned by a different key")]
    AlreadyOwned {
        /// The `.kin` name that is already registered.
        name: String,
    },
    /// A VDF task for this name is already running; only one at a time is permitted.
    /// The daemon prevents concurrent PoW computations for the same name to save CPU cycles.
    /// Wait for the current registration process to finish or fail.
    #[error("A VDF registration is already in progress for '{name}'")]
    AlreadyInProgress {
        /// The `.kin` name whose registration is already running.
        name: String,
    },
    /// The network rejected the registration record during the broadcast phase.
    /// The peers validated the payload and found it cryptographically or temporally invalid.
    /// Ensure your local clock is synced and you are using the latest network kyn.
    #[error("Registration rejected by the network: {reason}")]
    NetworkRejected {
        /// The specific reason the record was rejected.
        reason: RecordRejectReason,
    },
    /// An unexpected internal error occurred during the registration flow.
    /// A localized crash, database lock, or thread panic occurred inside the daemon.
    /// Check the daemon logs for stack traces and restart if necessary.
    #[error("Internal error: {message}")]
    Internal {
        /// Developer-facing description of what went wrong.
        message: String,
        /// Optional chain of underlying error causes.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    /// The name has not been registered on this node, so local operations cannot proceed.
    /// The daemon cannot perform actions (like publishing KIDs) on a name it does not control.
    /// Register the name on this node first, or import its private keys.
    #[error("No registration record found for {name}. Register the name first.")]
    NotRegisteredLocal {
        /// The `.kin` name.
        name: String,
    },
}

impl RegistrationError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidName { .. } => "KIN-REG-001",
            Self::VdfFailed(_) => "KIN-REG-002",
            Self::CommitmentMismatch => "KIN-REG-003",
            Self::AlreadyOwned { .. } => "KIN-REG-004",
            Self::AlreadyInProgress { .. } => "KIN-REG-005",
            Self::NetworkRejected { .. } => "KIN-REG-006",
            Self::Internal { .. } => "KIN-REG-007",
            Self::NotRegisteredLocal { .. } => "KIN-REG-008",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::VdfFailed(_))
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::InvalidName { .. } => Severity::Info,
            Self::VdfFailed(_) => Severity::Error,
            Self::CommitmentMismatch => Severity::Error,
            Self::AlreadyOwned { .. } => Severity::Info,
            Self::AlreadyInProgress { .. } => Severity::Info,
            Self::NetworkRejected { .. } => Severity::Warning,
            Self::Internal { .. } => Severity::Error,
            Self::NotRegisteredLocal { .. } => Severity::Info,
        }
    }

    /// Clean user-facing message with no developer details.
    pub fn user_message(&self) -> String {
        match self {
            Self::InvalidName { name } => format!(
                "'{}' contains invalid characters. Use only lowercase letters, digits, and hyphens.",
                name
            ),
            Self::VdfFailed(_) => "The VDF computation failed. Please try again.".to_string(),
            Self::CommitmentMismatch => {
                "The registration data is inconsistent. Please restart the registration process."
                    .to_string()
            }
            Self::AlreadyOwned { name } => {
                format!("'{}' is already registered by someone else.", name)
            }
            Self::AlreadyInProgress { name } => {
                format!("A registration is already in progress for '{}'.", name)
            }
            Self::NetworkRejected { reason } => format!("Registration was rejected: {}", reason),
            Self::Internal { .. } => "An internal error occurred during registration.".to_string(),
            Self::NotRegisteredLocal { name } => format!(
                "No registration record found for '{}'. Register the name first.",
                name
            ),
        }
    }

    /// Structured developer-facing details for [`ApiError`](crate::api_error::ApiError).
    pub fn details(&self) -> serde_json::Value {
        match self {
            Self::NetworkRejected { reason } => {
                serde_json::json!({ "reject_reason": reason.to_string() })
            }
            _ => serde_json::Value::Null,
        }
    }
}

impl PartialEq for ResolutionError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Offline, Self::Offline) => true,
            (
                Self::NotFound {
                    name: a_n,
                    peers_queried: a_p,
                },
                Self::NotFound {
                    name: b_n,
                    peers_queried: b_p,
                },
            ) => a_n == b_n && a_p == b_p,
            (
                Self::VdfVerificationFailed {
                    name: a_n,
                    count: a_c,
                },
                Self::VdfVerificationFailed {
                    name: b_n,
                    count: b_c,
                },
            ) => a_n == b_n && a_c == b_c,
            (
                Self::Expired {
                    name: a_n,
                    age: a_a,
                },
                Self::Expired {
                    name: b_n,
                    age: b_a,
                },
            ) => a_n == b_n && a_a == b_a,
            (
                Self::Timeout {
                    name: a_n,
                    elapsed_ms: a_e,
                    peers_queried: a_p,
                },
                Self::Timeout {
                    name: b_n,
                    elapsed_ms: b_e,
                    peers_queried: b_p,
                },
            ) => a_n == b_n && a_e == b_e && a_p == b_p,
            (Self::Internal { message: a_m, .. }, Self::Internal { message: b_m, .. }) => {
                a_m == b_m
            }
            _ => false,
        }
    }
}
impl Eq for ResolutionError {}

impl PartialEq for PublishError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Offline, Self::Offline) => true,
            (Self::InvalidProof(a), Self::InvalidProof(b)) => a == b,
            (Self::AlreadyOwned { name: a_n }, Self::AlreadyOwned { name: b_n }) => a_n == b_n,
            (Self::AllFailed { count: a_c }, Self::AllFailed { count: b_c }) => a_c == b_c,
            (Self::Internal { message: a_m, .. }, Self::Internal { message: b_m, .. }) => {
                a_m == b_m
            }
            _ => false,
        }
    }
}
impl Eq for PublishError {}

impl PartialEq for RegistrationError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::InvalidName { name: a_n }, Self::InvalidName { name: b_n }) => a_n == b_n,
            (Self::VdfFailed(a), Self::VdfFailed(b)) => a == b,
            (Self::CommitmentMismatch, Self::CommitmentMismatch) => true,
            (Self::AlreadyOwned { name: a_n }, Self::AlreadyOwned { name: b_n }) => a_n == b_n,
            (Self::AlreadyInProgress { name: a_n }, Self::AlreadyInProgress { name: b_n }) => {
                a_n == b_n
            }
            (Self::NetworkRejected { reason: a_r }, Self::NetworkRejected { reason: b_r }) => {
                a_r == b_r
            }
            (Self::Internal { message: a_m, .. }, Self::Internal { message: b_m, .. }) => {
                a_m == b_m
            }
            _ => false,
        }
    }
}
impl Eq for RegistrationError {}
