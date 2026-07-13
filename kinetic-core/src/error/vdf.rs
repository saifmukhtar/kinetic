use super::Severity;
use thiserror::Error;

/// Why a VDF proof was rejected.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum VdfRejectReason {
    /// The proof byte array was the wrong size or could not be parsed.
    #[error("proof bytes are malformed")]
    MalformedProof,
    /// The proof verified successfully, but for a different challenge than expected.
    #[error("proof does not match the challenge")]
    ChallengeMismatch,
    /// The underlying chiavdf verifier threw an internal error.
    #[error("VDF engine error: {0}")]
    EngineError(String),
    /// Generating the discriminant from the challenge failed.
    #[error("discriminant creation failed")]
    DiscriminantFailed,
}

/// Errors originating from the VDF engine
#[derive(Error, Debug, PartialEq, Eq)]
pub enum VdfError {
    /// The filesystem could not create the lock file needed to serialize VDF tasks.
    #[error("Failed to create VDF lock file: {0}")]
    LockFileError(String),
    /// A timeout or OS error occurred while attempting to acquire the VDF lock.
    #[error("Failed to acquire VDF lock: {0}")]
    LockAcquireError(String),
    /// Generating the discriminant from the challenge failed.
    #[error("Failed to create VDF discriminant")]
    DiscriminantError,
    /// The underlying chiavdf prover threw an internal error or panicked.
    #[error("Failed to generate VDF proof")]
    ProofGenerationError,
    /// The current architecture or OS is not supported by the embedded chiavdf library.
    #[error("VDF operation is unsupported on this platform")]
    UnsupportedPlatform,
}

impl VdfError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::LockFileError(_) => "KIN-VDF-001",
            Self::LockAcquireError(_) => "KIN-VDF-002",
            Self::DiscriminantError => "KIN-VDF-003",
            Self::ProofGenerationError => "KIN-VDF-004",
            Self::UnsupportedPlatform => "KIN-VDF-005",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.dev/errors/{}", self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::LockFileError(_) | Self::LockAcquireError(_) => Severity::Error,
            Self::DiscriminantError | Self::ProofGenerationError => Severity::Error,
            Self::UnsupportedPlatform => Severity::Critical,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::LockAcquireError(_))
    }

    /// Returns the `Display` representation as the user-facing message.
    pub fn user_message(&self) -> String {
        self.to_string()
    }
}
