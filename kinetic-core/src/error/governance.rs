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
    /// The mandatory 48-hour OTA update delay has not elapsed yet.
    #[error("OTA Update Timelock (48h) has not expired yet")]
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
    /// An EmergencyReset was attempted during Phase 1 (bootstrapping), which is meaningless.
    #[error("EmergencyReset is invalid during Phase 1 (unlocked state)")]
    EmergencyResetInPhase1,
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
    /// The founder has reached the strict 5-name limit for granting premium 1-letter names.
    #[error("Founder has reached the maximum allowed limit for granting premium names")]
    FounderPremiumLimitReached,
    /// A premium name grant/revoke was attempted on a name that is not exactly 1 character long.
    #[error("Premium name grants must be exactly 1 character long")]
    InvalidPremiumNameLength,
    /// Revoking a premium name is strictly reserved for the Council.
    #[error("Revoking a premium name requires the network to be in Council mode")]
    RevokeRequiresCouncilMode,
    /// The council has reached its maximum physical size (21 members).
    #[error("The council has reached its maximum capacity")]
    CouncilAtCapacity,
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
            Self::EmergencyResetInPhase1 => "KIN-GOV-017",
            Self::FounderPremiumLimitReached => "KIN-GOV-018",
            Self::InvalidPremiumNameLength => "KIN-GOV-019",
            Self::RevokeRequiresCouncilMode => "KIN-GOV-020",
            Self::CouncilAtCapacity => "KIN-GOV-021",
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
            | Self::InsufficientSignatures
            | Self::EmergencyResetInPhase1
            | Self::FounderPremiumLimitReached
            | Self::InvalidPremiumNameLength
            | Self::RevokeRequiresCouncilMode
            | Self::CouncilAtCapacity => Severity::Warning,
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
            Self::KeyLengthMismatch => "The provided cryptographic key is invalid. It must be exactly 32 bytes long.".to_string(),
            Self::StaleProposal => "The proposed governance action is too old and has been rejected to prevent replay attacks.".to_string(),
            Self::TimelockNotExpired => "The governance action is still in its mandatory waiting period and cannot be executed yet.".to_string(),
            Self::OtaTimelockNotExpired => "The OTA software update is still in its mandatory 48-hour waiting period.".to_string(),
            Self::NotPendingOrVetoed => "The target governance action is not currently pending in the queue, or it was already vetoed.".to_string(),
            Self::CouncilSizeMismatch => "The proposed action was rejected because it claimed a lower total council size than what is actively recorded on the network.".to_string(),
            Self::InvalidGuardSignature => "The Guard's signature provided for the veto is invalid or corrupted.".to_string(),
            Self::EmergencyResetVetoed => "The Emergency Reset action was permanently vetoed by the Guard key.".to_string(),
            Self::EmergencyResetRequiresRoot => "An Emergency Reset requires a valid signature from the Root key.".to_string(),
            Self::EmergencyResetRequiresGuard => "An Emergency Reset without the override flag requires a valid signature from the Guard key.".to_string(),
            Self::EmergencyResetInPhase1 => "An Emergency Reset cannot be performed because the network is still in Founder mode.".to_string(),
            Self::RotateRequiresGuard => "Rotating the Root key requires a valid signature from the Guard key.".to_string(),
            Self::UnhandledThresholdMath => "The governance action type is unrecognized and cannot be processed by the voting logic.".to_string(),
            Self::EmptyCouncil => "The council is currently empty. Actions must be performed by the Root key.".to_string(),
            Self::InsufficientSignatures => "The governance action does not have enough valid signatures to be executed.".to_string(),
            Self::FounderPremiumLimitReached => "The Founder has reached the maximum lifetime limit of 5 premium name grants.".to_string(),
            Self::InvalidPremiumNameLength => "Premium names governed by this action must be exactly 1 character long.".to_string(),
            Self::RevokeRequiresCouncilMode => "Premium names cannot be revoked while the network is in Founder mode. This action requires the network to be governed by the Council.".to_string(),
            Self::CouncilAtCapacity => "The council has reached its maximum capacity of 21 members. No new members can be appointed.".to_string(),
        }
    }
}
