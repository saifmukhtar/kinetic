use super::Severity;
use thiserror::Error;

/// Errors relating to Kinetic global governance actions.
#[derive(Error, Debug)]
pub enum GovernanceError {
    /// The `ROOT_PUBLIC_KEY_HEX` environment variable is absent; no governance can proceed.
    #[error("ROOT_PUBLIC_KEY_HEX is not configured. This is a fatal error.")]
    MissingRootKey,
    /// The `GUARD_PUBLIC_KEY_HEX` environment variable is absent; guard-gated actions are blocked.
    #[error("GUARD_PUBLIC_KEY_HEX is not configured. This is a fatal error.")]
    MissingGuardKey,
    /// A supplied public key byte slice is not exactly 32 bytes.
    #[error("Key must be 32 bytes")]
    KeyLengthMismatch,
    /// The governance proposal timestamp is older than the allowed replay window.
    #[error("Governance action too old, replay rejected")]
    StaleProposal,
    /// The mandatory delay after a council vote has not elapsed yet.
    #[error("Timelock has not expired yet")]
    TimelockNotExpired,
    /// The mandatory 24-hour OTA update delay has not elapsed yet.
    #[error("OTA Update Timelock (24h) has not expired yet")]
    OtaTimelockNotExpired,
    /// The target action hash is not in a pending-or-vetoed state.
    #[error("Target hash is not a pending timelock or was vetoed")]
    NotPendingOrVetoed,
    /// The proposal claims a smaller council size than is actually on-chain.
    #[error("Council size mismatch: proposer claimed an artificially low denominator")]
    CouncilSizeMismatch,
    /// The Guard's signature over the veto message is invalid.
    #[error("Invalid Guard signature for Veto")]
    InvalidGuardSignature,
    /// The Guard has permanently vetoed the EmergencyReset action.
    #[error("EmergencyReset has already been permanently vetoed by the Guard")]
    EmergencyResetVetoed,
    /// An EmergencyReset was attempted without a valid Root signature.
    #[error("EmergencyReset requires Root signature")]
    EmergencyResetRequiresRoot,
    /// An EmergencyReset (without override) was attempted without a valid Guard signature.
    #[error("EmergencyReset without override requires Guard signature")]
    EmergencyResetRequiresGuard,
    /// A root-key rotation was attempted without a valid Guard co-signature.
    #[error("RotateRootKey requires Guard signature")]
    RotateRequiresGuard,
    /// The requested threshold math is not handled by the standard council voting logic.
    #[error("Action not handled by standard threshold math")]
    UnhandledThresholdMath,
    /// The council is empty; all privileged actions must be performed directly by the Root key.
    #[error("Council is empty. Actions must be performed by Root Key.")]
    EmptyCouncil,
    /// The number of valid signatures does not meet the required threshold.
    #[error("Insufficient valid signatures")]
    InsufficientSignatures,
}

impl GovernanceError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingRootKey => "KIN-GOV-001",
            Self::MissingGuardKey => "KIN-GOV-002",
            Self::KeyLengthMismatch => "KIN-GOV-003",
            Self::StaleProposal => "KIN-GOV-004",
            Self::TimelockNotExpired => "KIN-GOV-005",
            Self::OtaTimelockNotExpired => "KIN-GOV-006",
            Self::NotPendingOrVetoed => "KIN-GOV-007",
            Self::CouncilSizeMismatch => "KIN-GOV-008",
            Self::InvalidGuardSignature => "KIN-GOV-009",
            Self::EmergencyResetVetoed => "KIN-GOV-010",
            Self::EmergencyResetRequiresRoot => "KIN-GOV-011",
            Self::EmergencyResetRequiresGuard => "KIN-GOV-012",
            Self::RotateRequiresGuard => "KIN-GOV-013",
            Self::UnhandledThresholdMath => "KIN-GOV-014",
            Self::EmptyCouncil => "KIN-GOV-015",
            Self::InsufficientSignatures => "KIN-GOV-016",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.dev/errors/{}", self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::MissingRootKey | Self::MissingGuardKey => Severity::Critical,
            Self::StaleProposal
            | Self::TimelockNotExpired
            | Self::OtaTimelockNotExpired
            | Self::NotPendingOrVetoed => Severity::Info,
            Self::KeyLengthMismatch
            | Self::CouncilSizeMismatch
            | Self::InvalidGuardSignature
            | Self::UnhandledThresholdMath => Severity::Error,
            Self::EmergencyResetVetoed
            | Self::EmergencyResetRequiresRoot
            | Self::EmergencyResetRequiresGuard
            | Self::RotateRequiresGuard
            | Self::EmptyCouncil
            | Self::InsufficientSignatures => Severity::Warning,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::TimelockNotExpired | Self::OtaTimelockNotExpired | Self::InsufficientSignatures
        )
    }

    /// Clean user-facing message with no developer details.
    pub fn user_message(&self) -> String {
        match self {
            Self::MissingRootKey => "The ROOT_PUBLIC_KEY_HEX environment variable is not set. This is a fatal configuration error.".to_string(),
            Self::MissingGuardKey => "The GUARD_PUBLIC_KEY_HEX environment variable is not set. This is a fatal configuration error.".to_string(),
            Self::StaleProposal => "The proposed governance action is too old and has been rejected to prevent replay attacks.".to_string(),
            Self::TimelockNotExpired => "The governance action is still in its mandatory waiting period and cannot be executed yet.".to_string(),
            Self::OtaTimelockNotExpired => "The OTA update is still in its mandatory 24-hour waiting period.".to_string(),
            Self::InsufficientSignatures => "The governance action does not have enough valid signatures to be executed.".to_string(),
            _ => self.to_string(),
        }
    }
}

