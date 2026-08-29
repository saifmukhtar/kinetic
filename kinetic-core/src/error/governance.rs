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
//!
//! > Note: `KIN-ACN-010`, `KIN-ACN-011`, and `KIN-ACN-012` are intentionally
//! > skipped in the stable code registry to allow for future expansion.
use super::Severity;
use thiserror::Error;

/// Errors relating to Kinetic global governance actions.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum GovernanceError {
    /// Missing Root Key. The `ROOT_PUBLIC_KEY_HEX` environment variable is absent; no governance can proceed.
    #[error("ROOT_PUBLIC_KEY_HEX is not configured. This is a fatal error.")]
    MissingRootKey,
    /// Malformed Root Key. The `ROOT_PUBLIC_KEY_HEX` string is present but is not valid hex.
    #[error("ROOT_PUBLIC_KEY_HEX is malformed and cannot be decoded as hex.")]
    MalformedRootKey,

    /// Key Length Mismatch. A supplied public key byte slice does not match the required length (e.g. 1,952 bytes for ML-DSA-65).
    #[error("Key length mismatch")]
    KeyLengthMismatch,
    /// Stale Proposal. The governance proposal timestamp is older than the allowed replay window.
    #[error("Governance action too old, replay rejected")]
    StaleProposal,
    /// Already Executed. The governance action has already been executed previously (replay attack).
    #[error("Governance action has already been executed")]
    AlreadyExecuted,

    /// Governance Disabled. Governance modifications are completely disabled in this network environment.
    #[error("Governance is disabled in permissionless mode")]
    GovernanceDisabled,

    /// Insufficient Signatures. The number of valid signatures does not meet the required threshold.
    #[error("Insufficient valid signatures")]
    InsufficientSignatures,
    /// Invalid Prime Length. A prime name mapping/unmapping was attempted on a name that is not exactly 1 character long.
    #[error("Prime name mappings must be exactly 1 character long")]
    InvalidPrimeLength,
    /// Invalid Protocol Name. A protocol name mapping/unmapping was attempted on a name not in the Category 2 list.
    #[error("Protocol name mappings must target a valid Category 2 protocol name")]
    InvalidProtocolName,
    /// Already Mapped. A name mapping was attempted on a name that is already mapped.
    #[error("Name is already mapped, explicitly unmap it first")]
    AlreadyMapped,
    /// Not Mapped. A name revoke was attempted on a name that is not currently mapped.
    #[error("Name is not currently mapped")]
    NotMapped,
    /// Unnormalized Name. A name mapping/unmapping payload was unnormalized (e.g. contains `.kin` suffix, mixed case, or whitespace).
    #[error(
        "Name payloads in governance actions must be strictly normalized (no .kin suffix, lowercase, length checks)"
    )]
    UnnormalizedName,
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
            Self::InsufficientSignatures => "KIN-ACN-007",
            Self::InvalidPrimeLength => "KIN-ACN-008",
            Self::InvalidProtocolName => "KIN-ACN-009",
            Self::AlreadyMapped => "KIN-ACN-010",
            Self::NotMapped => "KIN-ACN-011",
            Self::UnnormalizedName => "KIN-ACN-012",
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
