//! Governance action verification and voting error types (`KIN-GOV-NNN`).
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
//!
//! > Note: `KIN-GOV-010`, `KIN-GOV-011`, and `KIN-GOV-012` are intentionally
//! > skipped in the stable code registry to allow for future expansion.
use super::Severity;
use thiserror::Error;

/// Errors relating to Kinetic global governance actions.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum GovernanceError {
    /// The `ROOT_PUBLIC_KEY_HEX` environment variable is absent; no governance can proceed.
    #[error("ROOT_PUBLIC_KEY_HEX is not configured. This is a fatal error.")]
    MissingRootKey,
    /// The `ROOT_PUBLIC_KEY_HEX` string is present but is not valid hex.
    #[error("ROOT_PUBLIC_KEY_HEX is malformed and cannot be decoded as hex.")]
    MalformedRootKey,

    /// A supplied public key byte slice does not match the required length (e.g. 1,952 bytes for ML-DSA-65).
    #[error("Key length mismatch")]
    KeyLengthMismatch,
    /// The governance proposal timestamp is older than the allowed replay window.
    #[error("Governance action too old, replay rejected")]
    StaleProposal,
    /// The governance action has already been executed previously (replay attack).
    #[error("Governance action has already been executed")]
    AlreadyExecuted,

    /// Governance modifications are completely disabled in this network environment.
    #[error("Governance is disabled in permissionless mode")]
    GovernanceDisabled,

    /// The number of valid signatures does not meet the required threshold.
    #[error("Insufficient valid signatures")]
    InsufficientSignatures,
    /// A prime name mapping/unmapping was attempted on a name that is not exactly 1 character long.
    #[error("Prime name mappings must be exactly 1 character long")]
    InvalidPrimeLength,
    /// A protocol name mapping/unmapping was attempted on a name not in the Category 2 list.
    #[error("Protocol name mappings must target a valid Category 2 protocol name")]
    InvalidProtocolName,
    /// A name mapping was attempted on a name that is already mapped.
    #[error("Name is already mapped, explicitly unmap it first")]
    AlreadyMapped,
    /// A name revoke was attempted on a name that is not currently mapped.
    #[error("Name is not currently mapped")]
    NotMapped,
    /// A name mapping/unmapping payload was unnormalized (e.g. contains `.kin` suffix, mixed case, or whitespace).
    #[error(
        "Name payloads in governance actions must be strictly normalized (no .kin suffix, lowercase, length checks)"
    )]
    UnnormalizedName,
}

impl GovernanceError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingRootKey => "KIN-GOV-001",
            Self::MalformedRootKey => "KIN-GOV-008", // Next available ID
            Self::GovernanceDisabled => "KIN-GOV-002",
            Self::KeyLengthMismatch => "KIN-GOV-003",
            Self::StaleProposal => "KIN-GOV-004",
            Self::AlreadyExecuted => "KIN-GOV-009", // Next available ID

            Self::InsufficientSignatures => "KIN-GOV-016",
            Self::InvalidPrimeLength => "KIN-GOV-019",
            Self::InvalidProtocolName => "KIN-GOV-020",
            Self::AlreadyMapped => "KIN-GOV-013",
            Self::NotMapped => "KIN-GOV-014",
            Self::UnnormalizedName => "KIN-GOV-024",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::MissingRootKey | Self::MalformedRootKey => Severity::Critical,
            Self::StaleProposal | Self::AlreadyExecuted => Severity::Info,
            Self::KeyLengthMismatch => Severity::Error,
            Self::GovernanceDisabled
            | Self::InsufficientSignatures
            | Self::InvalidPrimeLength
            | Self::InvalidProtocolName
            | Self::AlreadyMapped
            | Self::NotMapped
            | Self::UnnormalizedName => Severity::Warning,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::InsufficientSignatures)
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
            Self::InsufficientSignatures => {
                "The message lacks the required cryptographic signatures to meet the required threshold.".to_string()
            }
            Self::InvalidPrimeLength => "Prime names governed by this action must be exactly 1 character long.".to_string(),
            Self::InvalidProtocolName => "Protocol names governed by this action must be valid Category 2 names.".to_string(),
            Self::AlreadyMapped => "The requested name is already mapped. It must be explicitly unmapped first.".to_string(),
            Self::NotMapped => "The requested name is not currently mapped.".to_string(),
            Self::UnnormalizedName => "The name payload must be strictly normalized (no .kin suffix, lowercase).".to_string(),
        }
    }
}
