//! Fine-grained error codes for the Kademlia record store.
//! Replaces the single overloaded `kad::store::Error::ValueTooLarge`
//! previously returned for 19+ completely different rejection reasons.

use kinetic_core::error::Severity;
use thiserror::Error;

/// Represents an error returned by the kinetic network storage or event loop layer.
#[derive(Error, Debug, Clone)]
pub enum KineticStoreError {
    /// The provided record payload exceeds the absolute 100KB network limit.
    /// To prevent DHT spam and memory exhaustion, the network rejects oversized records.
    /// Ensure JSON payloads are minified and unnecessary fields are stripped before publishing.
    #[error("payload exceeds maximum size limit")]
    PayloadTooLarge,
    /// The VDF proof attached to this record is too old to be accepted.
    /// The network requires PoW to be bound to recent Drand randomness to prevent pre-computation attacks.
    /// You must re-run the VDF sequencer using the latest network `kyn`.
    #[error("VDF proof has expired ({age} rounds old)")]
    VdfExpired {
        /// The age in rounds.
        age: u64,
    },
    /// The mathematical verification of the VDF proof failed.
    /// The proof string is either corrupted, maliciously forged, or does not match the difficulty.
    /// Check your VDF engine parameters and ensure the proof matches the submitted iterations.
    #[error("VDF proof is invalid")]
    InvalidVdf,
    /// The underlying VDF engine encountered a fatal execution error.
    /// The chiavdf process may have crashed or run out of memory during verification.
    /// Check system logs and ensure the VDF binary is correctly compiled for this architecture.
    #[error("VDF engine returned an error: {0}")]
    VdfEngineError(String),
    /// The cryptographic signature on the record failed Ed25519 verification.
    /// The record was likely corrupted in transit, or tampered with by a malicious peer.
    /// The network will automatically drop this record and ban the propagating peer.
    #[error("signature verification failed")]
    InvalidSignature,
    /// The public key bytes provided in the record are structurally invalid.
    /// The key cannot be parsed into a valid Ed25519 curve point.
    /// Ensure you are using 32-byte raw public keys, not PEM or ASN.1 encoded strings.
    #[error("public key bytes are malformed")]
    InvalidPublicKey,
    /// The signature bytes provided in the record are structurally invalid.
    /// The signature cannot be parsed into a valid 64-byte Ed25519 format.
    /// Ensure your signing pipeline outputs raw bytes, not hex or base64.
    #[error("signature bytes are malformed")]
    MalformedSignature,
    /// The submitted record lost the XOR distance tie-break against an existing record.
    /// Two records were submitted for the same name with the exact same VDF iterations, and yours lost the cryptographic coin toss.
    /// You must generate a new VDF proof with strictly more iterations to claim this name.
    #[error("lost the XOR tie-break against an existing record")]
    TieBroken,
    /// The VDF iterations provided are insufficient to override the existing active record.
    /// To steal or update an active name without authorization, you must provide a larger PoW proof than the current owner.
    /// Run the VDF sequencer longer to accumulate more iterations.
    #[error("insufficient VDF iterations to steal this name")]
    InsufficientIterations,
    /// The local Kademlia memory store encountered a fatal error while writing.
    /// This usually indicates the node is out of memory or the internal database is locked.
    /// Monitor node memory usage and restart the daemon if the issue persists.
    #[error("internal Kademlia DHT store failed to save the record")]
    InternalStoreError,
    /// The self-signature on the nested KID document failed verification.
    /// The document owner's signature does not match the DID public key.
    /// Ensure the KID document is signed by the exact key specified in its `id` field.
    #[error("KID document signature is invalid")]
    InvalidKidSignature,
    /// The signature on the delegated Manifest failed verification.
    /// The manifest was not signed by the parent KID's authorized capabilities key.
    /// Ensure the manifest is signed properly before attempting to publish.
    #[error("manifest signature is invalid")]
    InvalidManifestSignature,
    /// The record payload contains an unrecognized Kinetic prefix byte.
    /// The network only routes strictly typed records (e.g., KIDs, Manifests, Names, Routes).
    /// Ensure your client library is up to date with the latest Kinetic protocol spec.
    #[error("unknown record type prefix")]
    UnknownRecordType,
    /// The hex-encoded Drand randomness could not be decoded.
    /// The string is likely malformed, truncated, or contains non-hex characters.
    /// Ensure the Drand signature is a valid 96-byte BLS signature encoded as a 192-character hex string.
    #[error("drand_signature field contains invalid hex")]
    InvalidDrandHex,
    /// The heartbeat kyn is not strictly greater than the stored value (Finding 8).
    /// Heartbeats must strictly advance the kyn round to prevent replay attacks of old heartbeat packets.
    /// Wait for the next Drand round before broadcasting a new heartbeat.
    #[error("stale heartbeat: received kyn is not newer than existing record")]
    StaleHeartbeat,
    /// The HostRoutingRecord failed signature verification or timestamp check (Finding 13).
    /// The IP/PeerID routing data is either forged, signed by the wrong key, or dangerously stale.
    /// Generate a fresh routing record and sign it with the name's active capability key.
    #[error("HostRoutingRecord signature verification failed or record is stale")]
    InvalidHostRouteSignature,
    /// The node is rate-limiting reveal ingestion.
    /// Too many reveals were submitted from your IP/PeerID in a short window, triggering anti-spam protections.
    /// Back off and retry the submission later.
    #[error("rate limit exceeded for reveal submission")]
    RateLimited,
    /// The reveal commitment is too recent.
    /// The network enforces a minimum delay between publishing a commitment and revealing the data to prevent front-running.
    /// Wait the required number of Drand rounds before revealing.
    #[error("reveal commitment is too recent")]
    StaleReveal,
    /// The parsed JSON is valid, but violates the strict Kinetic protocol schema.
    /// Required fields are missing, or types do not match (e.g., string instead of integer).
    /// Check the protocol specification and validate your JSON payload locally before publishing.
    #[error("payload violates the expected record schema")]
    SchemaValidationError,
    /// The provided name is not a valid Kinetic apex name.
    /// Apex names must be alphanumeric, lowercase, and cannot contain hyphens or special characters.
    /// Correct the name string and try again.
    #[error("the provided name is not a valid kinetic apex name")]
    InvalidName,
    /// The network registration and renewals have been emergency paused.
    /// The global Root Key has temporarily halted the network, likely due to an active attack or critical upgrade.
    /// Monitor the official Kinetic network channels for status updates.
    #[error("network registration and renewals are currently halted")]
    NetworkHalted,
    /// The delegated manifest does not grant the required capability for this action.
    /// The master key did not authorize this sub-key to perform this specific network operation.
    /// You must sign the action with a key that holds the correct capability bit.
    #[error("delegated capability missing from authorized manifest")]
    DelegatedCapabilityMissing,
    /// The delegated authorization proof is structurally invalid or fails the signature check.
    /// The cryptographic chain of trust from the master DID to the delegate key is broken.
    /// Regenerate the authorization proof and ensure it is signed by the master key.
    #[error("delegated authorization proof is invalid")]
    DelegatedAuthorizationInvalid,
    /// The Drand BLS signature failed mathematical verification.
    /// The randomness injected into the PoW is forged or belongs to a different network/round.
    /// Ensure you are querying the correct League of Entropy Drand beacon.
    #[error("drand signature failed BLS verification")]
    InvalidDrandSignature,
    /// The raw payload bytes could not be parsed as JSON.
    /// The data is corrupted, encrypted, or improperly serialized.
    /// Ensure the payload is valid UTF-8 JSON.
    #[error("payload contains malformed or invalid JSON")]
    MalformedJson,
    /// The KID document failed its internal consistency validation.
    /// The document structure is flawed (e.g., duplicate capability keys, invalid contexts).
    /// Re-generate the KID document using the official SDK.
    #[error("kid document failed validation")]
    InvalidKidDocument,
    /// The initial DID binding failed on first publish.
    /// The cryptographic binding between the apex name and the genesis DID is invalid.
    /// Ensure the genesis signature covers the exact name and initial key material.
    #[error("genesis binding failed")]
    GenesisBindingFailed,
    /// The update is not authorized by the existing active record.
    /// You are attempting to modify a record without providing a valid signature from the current owner's key.
    /// Sign the update payload with the active authorized key.
    #[error("update is not authorized by prior key")]
    UnauthorizedUpdate,
    /// A manifest version rollback was detected.
    /// The network requires Manifest version numbers to be strictly monotonically increasing.
    /// Increment the manifest version number and re-sign before publishing.
    #[error("manifest version rollback detected")]
    ManifestVersionRollback,
    /// The delegated manifest failed its local cryptographic verification.
    /// The capabilities list, expiration, or signatures are structurally flawed.
    /// Regenerate the manifest using the official SDK to ensure correct field formatting.
    #[error("manifest local verification failed")]
    ManifestVerificationFailed,
    /// The heartbeat timestamp is set too far in the future.
    /// A node's clock is severely desynced or a peer is attempting to claim future rounds.
    /// Sync your system clock with an NTP server and retry.
    #[error("heartbeat timestamp is too far in the future")]
    FutureHeartbeat,
    /// The name type is classified as strictly immutable.
    /// Prime names and Infrastructure identities cannot be forcefully stolen via PoW.
    /// You must choose a standard kinetic apex name for registration.
    #[error("Prime and Infra names are immutable and cannot be stolen")]
    ImmutableName,
    
    // ==========================================
    // KIN-QRY Error Codes
    // ==========================================
    
    /// No existing reveal record was found for the requested name.
    /// The name may have expired, or the node has not yet synced this portion of the DHT.
    /// Check the spelling of the name and ensure the node is fully bootstrapped.
    #[error("no existing reveal found for this name")]
    RevealNotFound,
    /// The required prior commitment could not be found in the DHT.
    /// A reveal cannot be processed unless a valid commitment was published in a prior Drand round.
    /// Ensure the commitment was successfully published and confirmed before revealing.
    #[error("no prior commitment found in DHT")]
    MissingCommitment {
        /// The derived Kademlia DHT key of the missing commitment.
        commit_key: Vec<u8>,
    },
    /// The requested apex name could not be found in the local node cache.
    /// The name is not cached locally and requires an external DHT query.
    /// Use the DHT query API instead of the local cache endpoint.
    #[error("name not found locally")]
    NameNotFound,
    /// The required KID document is missing from the authorization payload.
    /// Certain network actions require the full KID document to be attached for capability verification.
    /// Attach the serialized KID document to the payload and retry.
    #[error("KID document is missing from the authorization payload")]
    MissingKidDocument,
}

impl KineticStoreError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::PayloadTooLarge => "KIN-DHT-001",
            Self::VdfExpired { .. } => "KIN-DHT-002",
            Self::InvalidVdf => "KIN-DHT-003",
            Self::VdfEngineError(_) => "KIN-DHT-004",
            Self::InvalidSignature => "KIN-DHT-005",
            Self::InvalidPublicKey => "KIN-DHT-006",
            Self::MalformedSignature => "KIN-DHT-007",
            Self::TieBroken => "KIN-DHT-008",
            Self::InsufficientIterations => "KIN-DHT-009",
            Self::InternalStoreError => "KIN-DHT-010",
            Self::InvalidKidSignature => "KIN-DHT-011",
            Self::InvalidManifestSignature => "KIN-DHT-012",
            Self::UnknownRecordType => "KIN-DHT-013",
            Self::InvalidDrandHex => "KIN-DHT-014",
            Self::StaleHeartbeat => "KIN-DHT-015",
            Self::InvalidHostRouteSignature => "KIN-DHT-016",
            Self::RateLimited => "KIN-DHT-017",
            Self::StaleReveal => "KIN-DHT-018",
            Self::SchemaValidationError => "KIN-DHT-019",
            Self::InvalidName => "KIN-DHT-020",
            Self::NetworkHalted => "KIN-DHT-021",
            Self::DelegatedCapabilityMissing => "KIN-DHT-022",
            Self::DelegatedAuthorizationInvalid => "KIN-DHT-023",
            Self::InvalidDrandSignature => "KIN-DHT-024",
            Self::MalformedJson => "KIN-DHT-025",
            Self::InvalidKidDocument => "KIN-DHT-026",
            Self::GenesisBindingFailed => "KIN-DHT-027",
            Self::UnauthorizedUpdate => "KIN-DHT-028",
            Self::ManifestVersionRollback => "KIN-DHT-029",
            Self::ManifestVerificationFailed => "KIN-DHT-030",
            Self::FutureHeartbeat => "KIN-DHT-031",
            Self::ImmutableName => "KIN-DHT-032",

            Self::RevealNotFound => "KIN-QRY-007",
            Self::MissingCommitment { .. } => "KIN-QRY-008",
            Self::NameNotFound => "KIN-QRY-009",
            Self::MissingKidDocument => "KIN-QRY-010",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.network/errors/{}", self.code())
    }

    /// Returns whether this error is transient and retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::RateLimited | Self::VdfEngineError(_))
    }

    /// Human-friendly explanation of the error.
    pub fn user_message(&self) -> String {
        match self {
            Self::PayloadTooLarge => "Record payload exceeds maximum allowed size".to_string(),
            Self::VdfExpired { age } => format!("VDF proof is expired ({} rounds old)", age),
            Self::InvalidVdf => "VDF proof verification failed".to_string(),
            Self::VdfEngineError(err) => format!("VDF engine error: {}", err),
            Self::InvalidSignature => "Signature verification failed".to_string(),
            Self::InvalidPublicKey => "Public key format is invalid".to_string(),
            Self::MalformedSignature => "Signature format is invalid".to_string(),
            Self::TieBroken => "Record lost XOR tie-break against existing DHT entry".to_string(),
            Self::InsufficientIterations => {
                "Insufficient VDF iterations to override existing record".to_string()
            }
            Self::InternalStoreError => {
                "Internal DHT memory store rejected the put operation".to_string()
            }
            Self::InvalidKidSignature => "KID document signature verification failed".to_string(),
            Self::InvalidManifestSignature => "Manifest signature verification failed".to_string(),
            Self::UnknownRecordType => "Record payload prefix is unrecognized".to_string(),
            Self::InvalidDrandHex => "Drand randomness hex string is invalid".to_string(),
            Self::StaleHeartbeat => "Heartbeat kyn is not newer than stored record".to_string(),
            Self::InvalidHostRouteSignature => {
                "Host routing record signature verification failed".to_string()
            }
            Self::RateLimited => "Rate limit exceeded for submission".to_string(),
            Self::StaleReveal => "Reveal commitment is too recent".to_string(),
            Self::SchemaValidationError => "Parsed JSON failed strict type validation".to_string(),
            Self::InvalidName => "Name is not a valid Kinetic apex name".to_string(),
            Self::NetworkHalted => "Network Registration Halted".to_string(),
            Self::DelegatedCapabilityMissing => {
                "The delegated manifest does not grant the required capability for this action."
                    .to_string()
            }
            Self::DelegatedAuthorizationInvalid => {
                "The delegated authorization proof could not be verified against the master key."
                    .to_string()
            }
            Self::InvalidDrandSignature => "Drand signature math verification failed".to_string(),
            Self::MalformedJson => "Failed to parse raw bytes as JSON".to_string(),
            Self::InvalidKidDocument => "KID document failed self-verification".to_string(),
            Self::GenesisBindingFailed => "KID genesis binding failed on first publish".to_string(),
            Self::UnauthorizedUpdate => {
                "KID update is not authorized by existing active record".to_string()
            }
            Self::ManifestVersionRollback => {
                "Manifest version must be strictly increasing".to_string()
            }
            Self::ManifestVerificationFailed => "Manifest failed local verification".to_string(),
            Self::FutureHeartbeat => "Heartbeat timestamp is from the future".to_string(),
            Self::ImmutableName => {
                "This name type is immortal and cannot be transferred via PoW".to_string()
            }

            Self::RevealNotFound => "No reveal record found for name".to_string(),
            Self::MissingCommitment { .. } => {
                "No prior commitment found in DHT for this reveal".to_string()
            }
            Self::NameNotFound => "Active record missing for this name".to_string(),
            Self::MissingKidDocument => {
                "Authorization payload is missing the required KID document".to_string()
            }
        }
    }

    /// Returns the severity level of this error.
    pub fn severity(&self) -> Severity {
        match self {
            Self::TieBroken
            | Self::InsufficientIterations
            | Self::VdfExpired { .. }
            | Self::RevealNotFound
            | Self::NameNotFound => Severity::Info,
            Self::PayloadTooLarge | Self::UnknownRecordType | Self::RateLimited => {
                Severity::Warning
            }
            Self::InvalidVdf
            | Self::InvalidSignature
            | Self::InvalidPublicKey
            | Self::MalformedSignature
            | Self::VdfEngineError(_)
            | Self::InvalidKidSignature
            | Self::InvalidManifestSignature
            | Self::InvalidDrandHex
            | Self::StaleHeartbeat
            | Self::InvalidHostRouteSignature
            | Self::StaleReveal
            | Self::MissingCommitment { .. }
            | Self::InvalidName
            | Self::NetworkHalted
            | Self::DelegatedCapabilityMissing
            | Self::DelegatedAuthorizationInvalid
            | Self::InvalidDrandSignature
            | Self::InvalidKidDocument
            | Self::GenesisBindingFailed
            | Self::UnauthorizedUpdate
            | Self::ManifestVersionRollback
            | Self::ManifestVerificationFailed
            | Self::FutureHeartbeat
            | Self::ImmutableName
            | Self::MissingKidDocument
            | Self::MalformedJson
            | Self::SchemaValidationError
            | Self::InternalStoreError => Severity::Error,
        }
    }

    /// Logs the error utilizing its severity level with contextual fields
    pub fn log_warning(&self, name: &str, extra_context: &str) {
        let severity = self.severity();
        let error_code = self.code();
        match severity {
            Severity::Info => tracing::info!(
                error_code = error_code,
                name = name,
                severity = ?severity,
                "{} {}", extra_context, self
            ),
            Severity::Warning => tracing::warn!(
                error_code = error_code,
                name = name,
                severity = ?severity,
                "{} {}", extra_context, self
            ),
            _ => tracing::error!(
                error_code = error_code,
                name = name,
                severity = ?severity,
                "{} {}", extra_context, self
            ),
        }
    }
}

// Map to the libp2p expected error type.
// The specific KineticStoreError is logged before this conversion is made.
impl From<KineticStoreError> for libp2p::kad::store::Error {
    fn from(_e: KineticStoreError) -> Self {
        libp2p::kad::store::Error::ValueTooLarge
    }
}
