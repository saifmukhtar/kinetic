//! Governance action verification and voting error types (`KIN-GOV-NNN`).
//!
//! [`GovernanceError`] is returned by the active [`GovernanceEngine`](crate::traits::GovernanceEngine)
//! when a [`SignedGovernanceMessage`](crate::governance::types::SignedGovernanceMessage) fails
//! signature verification, threshold checks, or timelock constraints.
//!
//! ## Protocol Context
//!
//! Kinetic governance is pluggable: `network.json` selects one of four engines
//! (`sovereign`, `council`, `permissionless`) at compile time. Each engine
//! runs `verify_action()` before any state mutation occurs.
//!
//! Key roles:
//! - **Root key**: Ultimate authority; can ratify any action in Founder phase.
//! - **Guard key**: Emergency veto key for OTA updates and root key rotation.
//! - **Council members**: Vote on proposals; majority/supermajority required.
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

    /// A supplied public key byte slice does not match the required length (e.g. 1,952 bytes for ML-DSA-65).
    #[error("Key length mismatch")]
    KeyLengthMismatch,
    /// The governance proposal timestamp is older than the allowed replay window.
    #[error("Governance action too old, replay rejected")]
    StaleProposal,
    /// The mandatory delay after a council vote has not elapsed yet.
    #[error("Timelock has not expired yet")]
    TimelockNotExpired,

    /// The target action hash is not in a pending-or-vetoed state.
    #[error("Target hash is not a pending timelock or was vetoed")]
    NotPendingOrVetoed,

    /// Governance modifications are completely disabled in this network environment.
    #[error("Governance is disabled in permissionless mode")]
    GovernanceDisabled,

    /// The number of valid signatures does not meet the required threshold.
    #[error("Insufficient valid signatures")]
    InsufficientSignatures,
    /// A premium name grant/revoke was attempted on a name that is not exactly 1 character long.
    #[error("Premium name grants must be exactly 1 character long")]
    InvalidPremiumNameLength,
    /// An infrastructure name grant/revoke was attempted on a name not in the Category 2 list.
    #[error("Infrastructure name grants must target a valid Category 2 infrastructure name")]
    InvalidInfrastructureName,
}

impl GovernanceError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingRootKey => "KIN-GOV-001",
            Self::GovernanceDisabled => "KIN-GOV-002",
            Self::KeyLengthMismatch => "KIN-GOV-003",
            Self::StaleProposal => "KIN-GOV-004",
            Self::TimelockNotExpired => "KIN-GOV-005",

            Self::NotPendingOrVetoed => "KIN-GOV-007",

            Self::InsufficientSignatures => "KIN-GOV-016",
            Self::InvalidPremiumNameLength => "KIN-GOV-019",
            Self::InvalidInfrastructureName => "KIN-GOV-020",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::MissingRootKey => Severity::Critical,
            Self::StaleProposal | Self::TimelockNotExpired | Self::NotPendingOrVetoed => {
                Severity::Info
            }
            Self::KeyLengthMismatch => Severity::Error,
            Self::InsufficientSignatures
            | Self::GovernanceDisabled
            | Self::InvalidPremiumNameLength
            | Self::InvalidInfrastructureName => Severity::Warning,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::TimelockNotExpired | Self::InsufficientSignatures
        )
    }

    /// Clean user-facing message with no developer details.
    pub fn user_message(&self) -> String {
        match self {
            Self::MissingRootKey => "The ROOT_PUBLIC_KEY_HEX environment variable is not set. This is a fatal configuration error.".to_string(),

            Self::KeyLengthMismatch => "The provided cryptographic key length is invalid.".to_string(),
            Self::StaleProposal => "The proposed governance action is too old and has been rejected to prevent replay attacks.".to_string(),
            Self::TimelockNotExpired => "The governance action is still in its mandatory waiting period and cannot be executed yet.".to_string(),

            Self::NotPendingOrVetoed => {
                "The requested governance hash is not in a modifiable pending state.".to_string()
            }
            Self::GovernanceDisabled => {
                "The network is operating in permissionless mode where governance actions are universally rejected.".to_string()
            }
            Self::InsufficientSignatures => {
                "The message lacks the required cryptographic signatures to meet the council quorum threshold.".to_string()
            }
            Self::InvalidPremiumNameLength => "Premium names governed by this action must be exactly 1 character long.".to_string(),
            Self::InvalidInfrastructureName => "Infrastructure names governed by this action must be valid Category 2 names.".to_string(),
        }
    }
}
