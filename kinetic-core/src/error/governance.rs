//! Governance action verification and voting error types (`KIN-GOV-NNN`).
//!
//! [`GovernanceError`] is returned by the active [`GovernanceEngine`](crate::traits::GovernanceEngine)
//! when a [`SignedGovernanceMessage`](crate::governance::types::SignedGovernanceMessage) fails
//! signature verification, threshold checks, or timelock constraints.
//!
//! ## Protocol Context
//!
//! Kinetic governance is pluggable: `network.json` selects one of four engines
//! (`bicameral`, `monarchy`, `council`, `anarchy`) at compile time. Each engine
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

    /// A supplied public key byte slice is not exactly 32 bytes.
    #[error("Key must be 32 bytes")]
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
    /// The proposal claims a smaller council size than is actually on-chain.
    #[error("Council size mismatch: proposer claimed an artificially low denominator")]
    CouncilSizeMismatch,

    /// The requested threshold math is not handled by the standard council voting logic.
    #[error("Action not handled by standard threshold math")]
    UnhandledThresholdMath,
    /// The council is empty; all privileged actions must be performed directly by the Root key.
    #[error("Council is empty. Actions must be performed by Root Key.")]
    EmptyCouncil,
    /// The number of valid signatures does not meet the required threshold.
    #[error("Insufficient valid signatures")]
    InsufficientSignatures,
    /// The founder has reached the strict 5-name limit for granting premium 1-letter names.
    #[error("Founder has reached the maximum allowed limit for granting premium names")]
    FounderPremiumLimitReached,
    /// A premium name grant/revoke was attempted on a name that is not exactly 1 character long.
    #[error("Premium name grants must be exactly 1 character long")]
    InvalidPremiumNameLength,

    /// The council has reached its maximum physical size (21 members).
    #[error("The council has reached its maximum capacity")]
    CouncilAtCapacity,

}

impl GovernanceError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingRootKey => "KIN-GOV-001",

            Self::KeyLengthMismatch => "KIN-GOV-003",
            Self::StaleProposal => "KIN-GOV-004",
            Self::TimelockNotExpired => "KIN-GOV-005",

            Self::NotPendingOrVetoed => "KIN-GOV-007",
            Self::CouncilSizeMismatch => "KIN-GOV-008",

            Self::UnhandledThresholdMath => "KIN-GOV-014",
            Self::EmptyCouncil => "KIN-GOV-015",
            Self::InsufficientSignatures => "KIN-GOV-016",
            Self::FounderPremiumLimitReached => "KIN-GOV-018",
            Self::InvalidPremiumNameLength => "KIN-GOV-019",

            Self::CouncilAtCapacity => "KIN-GOV-021",

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
            Self::StaleProposal
            | Self::TimelockNotExpired
            | Self::NotPendingOrVetoed => Severity::Info,
            Self::KeyLengthMismatch
            | Self::CouncilSizeMismatch
            | Self::UnhandledThresholdMath => Severity::Error,
            Self::EmptyCouncil
            | Self::InsufficientSignatures
            | Self::FounderPremiumLimitReached
            | Self::InvalidPremiumNameLength
            | Self::CouncilAtCapacity => Severity::Warning,
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

            Self::KeyLengthMismatch => "The provided cryptographic key is invalid. It must be exactly 32 bytes long.".to_string(),
            Self::StaleProposal => "The proposed governance action is too old and has been rejected to prevent replay attacks.".to_string(),
            Self::TimelockNotExpired => "The governance action is still in its mandatory waiting period and cannot be executed yet.".to_string(),

            Self::NotPendingOrVetoed => "The target governance action is not currently pending in the queue, or it was already vetoed.".to_string(),
            Self::CouncilSizeMismatch => "The proposed action was rejected because it claimed a lower total council size than what is actively recorded on the network.".to_string(),

            Self::UnhandledThresholdMath => "The governance action type is unrecognized and cannot be processed by the voting logic.".to_string(),
            Self::EmptyCouncil => "The council is currently empty. Actions must be performed by the Root key.".to_string(),
            Self::InsufficientSignatures => "The governance action does not have enough valid signatures to be executed.".to_string(),
            Self::FounderPremiumLimitReached => "The Founder has reached the maximum lifetime limit of 5 premium name grants.".to_string(),
            Self::InvalidPremiumNameLength => "Premium names governed by this action must be exactly 1 character long.".to_string(),

            Self::CouncilAtCapacity => "The council has reached its maximum capacity of 21 members. No new members can be appointed.".to_string(),

        }
    }
}
