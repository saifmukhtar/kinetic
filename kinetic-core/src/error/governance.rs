//! Governance action verification and voting error types (`KIN-ACN-NNN`).
//!
//! [`GovernanceError`] is returned by the active [`GovernanceEngine`](crate::traits::GovernanceEngine)
//! when a [`SignedGovernanceMessage`](crate::governance::types::SignedGovernanceMessage) fails
//! signature verification, threshold checks, or timelock constraints.
//!
//! ## Protocol Context
//!
//! Kinetic governance is pluggable: `network.json` selects one of the engines
//! (`sovereign` or `permissionless`) at compile time. Each engine
//! runs `verify_action()` before any state mutation occurs.
//!
//! Key roles:
//! - **Root key**: Ultimate authority; can ratify any action in Sovereign phase.
use super::Severity;
use thiserror::Error;

/// Errors relating to Kinetic global governance actions.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum GovernanceError {
    /// The daemon started in Sovereign mode but the `ROOT_PUBLIC_KEY_HEX` environment variable is missing.
    /// The node will refuse to start because it cannot verify incoming governance actions.
    #[error("ROOT_PUBLIC_KEY_HEX is not configured. This is a fatal error.")]
    MissingRootKey,

    /// The provided `ROOT_PUBLIC_KEY_HEX` contains invalid characters and cannot be decoded.
    /// Ensure the variable contains a valid, clean hex string without spaces or newlines.
    #[error("ROOT_PUBLIC_KEY_HEX is malformed and cannot be decoded as hex.")]
    MalformedRootKey,

    /// A supplied public key byte slice does not match the required length for the algorithm.
    /// For example, ML-DSA-65 keys must be exactly 1,952 bytes long.
    #[error("Key length mismatch")]
    KeyLengthMismatch,

    /// The proposed governance action is older than the allowed replay window.
    /// This protects the network from malicious actors trying to execute delayed replay attacks.
    #[error("Governance action too old, replay rejected")]
    StaleProposal,

    /// The governance action has already been executed on the network and its hash is cached.
    /// This protects against immediate replay attacks.
    #[error("Governance action has already been executed")]
    AlreadyExecuted,

    /// The node is running in permissionless mode where global governance actions are universally rejected.
    /// This happens if someone tries to broadcast a governance command to a permissionless network.
    #[error("Governance is disabled in permissionless mode")]
    GovernanceDisabled,

    /// The message signature failed cryptographic verification against the root key.
    /// This happens if the payload was tampered with or signed by an unauthorized key.
    #[error("Invalid signature")]
    InvalidSignature,

    /// A prime name mapping or unmapping was attempted on a name that is not exactly 1 character long.
    /// Prime names (like 'a.kin') are strictly reserved.
    #[error("Prime name mappings must be exactly 1 character long")]
    InvalidPrimeLength,

    /// A protocol name mapping was attempted on a name that is not whitelisted in the Category 2 protocols list.
    #[error("Protocol name mappings must target a valid Category 2 protocol name")]
    InvalidProtocolName,

    /// A governance action attempted to map a name that is already currently mapped.
    /// You must explicitly unmap it first by publishing a revocation action before remapping.
    #[error("Name is already mapped, explicitly unmap it first")]
    AlreadyMapped,

    /// A governance action attempted to revoke or unmap a name that does not exist in the current state.
    #[error("Name is not currently mapped")]
    NotMapped,

    /// The name payload in the governance action was unnormalized.
    /// Payloads must be strictly normalized (no `.kin` suffix, strictly lowercase) before being signed.
    #[error(
        "Name payloads in governance actions must be strictly normalized (no .kin suffix, lowercase, length checks)"
    )]
    UnnormalizedName,

    /// The daemon could not persist the updated governance state to disk.
    /// Check disk space and permissions for the `base_dir/networks/nsp-salt_id/` directory.
    #[error("Failed to save modified governance state to disk")]
    StateSaveFailed,

    /// P2P Publish Failed. The local node successfully verified the action, but could not broadcast it to the libp2p network.
    #[error("Failed to publish Governance Message to P2P network")]
    P2pPublishFailed,

    /// Invalid Seed State. A bootstrap seed node provided governance bytes that failed decoding or validation.
    #[error("Seed node provided invalid governance state bytes")]
    InvalidSeedState,

    /// State Corrupted. The local governance JSON state file on disk is corrupted and cannot be parsed.
    /// The daemon will refuse to start to avoid overwriting valid network state.
    #[error("Governance state corrupted")]
    StateCorrupted,

    /// State Read Failed. The local governance file could not be read (e.g. missing file or bad permissions).
    #[error("Failed to read Governance state file")]
    StateReadFailed,

    /// Bootstrap Fetch Failed. The node failed to pull the initial governance state from any bootstrap peers.
    #[error("Failed to fetch governance state from any bootstrap node")]
    BootstrapFetchFailed,
}

impl GovernanceError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingRootKey => "KIN-ACN-001",
            Self::MalformedRootKey => "KIN-ACN-002",
            Self::GovernanceDisabled => "KIN-ACN-003",
            Self::KeyLengthMismatch => "KIN-ACN-004",
            Self::StaleProposal => "KIN-ACN-005",
            Self::AlreadyExecuted => "KIN-ACN-006",
            Self::InvalidSignature => "KIN-ACN-007",
            Self::InvalidPrimeLength => "KIN-ACN-008",
            Self::InvalidProtocolName => "KIN-ACN-009",
            Self::AlreadyMapped => "KIN-ACN-010",
            Self::NotMapped => "KIN-ACN-011",
            Self::UnnormalizedName => "KIN-ACN-012",
            Self::StateSaveFailed => "KIN-ACN-013",
            Self::P2pPublishFailed => "KIN-ACN-014",
            Self::InvalidSeedState => "KIN-ACN-015",
            Self::StateCorrupted => "KIN-ACN-016",
            Self::StateReadFailed => "KIN-ACN-017",
            Self::BootstrapFetchFailed => "KIN-ACN-018",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::MissingRootKey | Self::MalformedRootKey | Self::StateCorrupted => Severity::Critical,
            Self::StaleProposal | Self::AlreadyExecuted => Severity::Info,
            Self::KeyLengthMismatch | Self::StateSaveFailed | Self::P2pPublishFailed | Self::StateReadFailed => Severity::Error,
            Self::GovernanceDisabled
            | Self::InvalidSignature
            | Self::InvalidPrimeLength
            | Self::InvalidProtocolName
            | Self::AlreadyMapped
            | Self::NotMapped
            | Self::InvalidSeedState
            | Self::BootstrapFetchFailed
            | Self::UnnormalizedName => Severity::Warning,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::InvalidSignature | Self::P2pPublishFailed | Self::BootstrapFetchFailed)
    }

    /// Clean user-facing message with no developer details.
    pub fn user_message(&self) -> String {
        match self {
            Self::MissingRootKey => "The ROOT_PUBLIC_KEY_HEX environment variable is not set. This is a fatal configuration error.".to_string(),
            Self::MalformedRootKey => "The ROOT_PUBLIC_KEY_HEX environment variable contains invalid characters and cannot be decoded.".to_string(),

            Self::KeyLengthMismatch => "The provided cryptographic key length is invalid.".to_string(),
            Self::StaleProposal => "The proposed governance action is too old and has been rejected to prevent replay attacks.".to_string(),
            Self::AlreadyExecuted => "The proposed governance action has already been executed on the network and cannot be replayed.".to_string(),

            Self::GovernanceDisabled => {
                "The network is operating in permissionless mode where governance actions are universally rejected.".to_string()
            }
            Self::InvalidSignature => {
                "The message signature does not cryptographically match the configured root key.".to_string()
            }
            Self::InvalidPrimeLength => "Prime names governed by this action must be exactly 1 character long.".to_string(),
            Self::InvalidProtocolName => "Protocol names governed by this action must be valid Category 2 names.".to_string(),
            Self::AlreadyMapped => "The requested name is already mapped. It must be explicitly unmapped first.".to_string(),
            Self::NotMapped => "The requested name is not currently mapped.".to_string(),
            Self::UnnormalizedName => "The name payload must be strictly normalized (no .kin suffix, lowercase).".to_string(),
            Self::StateSaveFailed => "Failed to save the modified governance state to disk.".to_string(),
            Self::P2pPublishFailed => "Failed to broadcast the governance message to the P2P network.".to_string(),
            Self::InvalidSeedState => "A bootstrap seed node provided an invalid governance state.".to_string(),
            Self::StateCorrupted => "The local governance state file is corrupted.".to_string(),
            Self::StateReadFailed => "Failed to read the local governance state file from disk.".to_string(),
            Self::BootstrapFetchFailed => "Failed to pull governance state from bootstrap nodes.".to_string(),
        }
    }
}
