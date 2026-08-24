//! VDF engine error types (`KIN-VDF-NNN`).
//!
//! Two complementary enums cover the full VDF error surface:
//!
//! - [`VdfRejectReason`] — proof-level rejection; used by the DHT store verifier
//!   when a submitted proof from a peer cannot be verified against its challenge.
//! - [`VdfError`] — engine-level failure; used by the VDF prover when generating
//!   a new proof for the local node's own registrations.
//!
//! ## Protocol Context
//!
//! Kinetic uses a Wesolowski RSA VDF (pure Rust, no C++ dependencies) where
//! the challenge is derived from Drand randomness at commitment time:
//! `challenge = SHA-256(network_id || name || salt || drand_signature_hex)`.
//!
//! The Prover uses Boneh-Bünz-Fisch Blockwise Checkpointing to bound memory
//! usage to ~100MB regardless of iteration count.
//!
//! [`VdfError::LockAcquireError`] (`KIN-VDF-002`) is the only retryable variant.
use super::Severity;
use thiserror::Error;

/// Strict validation errors for a Reveal payload.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum RevealValidationError {
    /// The protocol version is unsupported.
    #[error("Invalid protocol version {0}. Only protocol version 1 is supported.")]
    InvalidProtocolVersion(u8),
    /// The domain name fails apex validation rules.
    #[error("Invalid name: {0}")]
    InvalidName(#[from] crate::error::NamesError),
    /// The payload size exceeds the protocol maximum.
    #[error("Payload size {0} exceeds MAX_PAYLOAD_SIZE {1}")]
    PayloadTooLarge(usize, usize),
    /// The Drand signature length is incorrect.
    #[error("Invalid drand_signature length: expected {0}, got {1}")]
    InvalidDrandSignatureLength(usize, usize),
    /// The ML-DSA public key length is incorrect.
    #[error("Invalid pubkey length: expected {0}, got {1}")]
    InvalidPubkeyLength(usize, usize),
    /// The ML-DSA signature length is incorrect.
    #[error("Invalid signature length: expected {0}, got {1}")]
    InvalidSignatureLength(usize, usize),
    /// The VDF proof size exceeds the maximum allowed length.
    #[error("VDF proof size {0} exceeds maximum {1}")]
    VdfProofTooLarge(usize, usize),
}

impl RevealValidationError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidProtocolVersion(_) => "KIN-RVL-001",
            Self::InvalidName(err) => err.code(),
            Self::PayloadTooLarge(_, _) => "KIN-RVL-002",
            Self::InvalidDrandSignatureLength(_, _) => "KIN-RVL-003",
            Self::InvalidPubkeyLength(_, _) => "KIN-RVL-004",
            Self::InvalidSignatureLength(_, _) => "KIN-RVL-005",
            Self::VdfProofTooLarge(_, _) => "KIN-RVL-006",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::InvalidName(_) => Severity::Warning,
            _ => Severity::Error,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::InvalidProtocolVersion(_) => {
                "The network protocol version is unsupported.".to_string()
            }
            Self::InvalidName(err) => err.user_message(),
            Self::PayloadTooLarge(_, _) => {
                "The data payload exceeds the maximum allowed size.".to_string()
            }
            Self::InvalidDrandSignatureLength(_, _) => {
                "The embedded randomness signature is the wrong size.".to_string()
            }
            Self::InvalidPubkeyLength(_, _) => {
                "The ML-DSA public key is the wrong size.".to_string()
            }
            Self::InvalidSignatureLength(_, _) => {
                "The ML-DSA signature is the wrong size.".to_string()
            }
            Self::VdfProofTooLarge(_, _) => "The embedded VDF proof is too large.".to_string(),
        }
    }
}

/// Why a VDF proof was rejected.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum VdfRejectReason {
    /// The proof byte array was the wrong size or could not be parsed.
    #[error("proof bytes are malformed")]
    MalformedProof,
    /// The proof verified successfully, but for a different challenge than expected.
    #[error("proof does not match the challenge")]
    ChallengeMismatch,
    /// The underlying VDF verifier threw an internal error.
    #[error("VDF engine error: {0}")]
    EngineError(String),
    /// Generating the discriminant from the challenge failed.
    #[error("discriminant creation failed")]
    DiscriminantFailed,
}

impl VdfRejectReason {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MalformedProof => "KIN-VDF-101",
            Self::ChallengeMismatch => "KIN-VDF-102",
            Self::EngineError(_) => "KIN-VDF-103",
            Self::DiscriminantFailed => "KIN-VDF-104",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::MalformedProof | Self::ChallengeMismatch => Severity::Warning,
            Self::EngineError(_) | Self::DiscriminantFailed => Severity::Error,
        }
    }

    /// Whether the client should offer a retry action.
    /// Proof rejections are never retryable — the same proof will always fail.
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::MalformedProof => {
                "The submitted VDF proof is malformed or the wrong size.".to_string()
            }
            Self::ChallengeMismatch => {
                "The submitted VDF proof does not match the expected challenge.".to_string()
            }
            Self::EngineError(_) => "An internal VDF verification error occurred.".to_string(),
            Self::DiscriminantFailed => {
                "Failed to derive the VDF challenge discriminant.".to_string()
            }
        }
    }
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
    /// The underlying VDF prover threw an internal error or panicked.
    #[error("Failed to generate VDF proof")]
    ProofGenerationError,
    /// The current architecture or OS is not supported by the embedded VDF library.
    #[error("VDF operation is unsupported on this platform")]
    UnsupportedPlatform,
    /// The proof exceeds acceptable bounds or is malformed before parsing.
    #[error("VDF proof is structurally invalid or too large")]
    InvalidProof,
    /// The challenge is degenerate (e.g. all-zero) and would produce a universally-forgeable proof.
    #[error("VDF challenge is degenerate and cannot be safely evaluated")]
    InvalidChallenge,
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
            Self::InvalidProof => "KIN-VDF-006",
            Self::InvalidChallenge => "KIN-VDF-007",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::LockFileError(_) | Self::LockAcquireError(_) => Severity::Error,
            Self::DiscriminantError | Self::ProofGenerationError | Self::InvalidProof => {
                Severity::Error
            }
            Self::UnsupportedPlatform => Severity::Critical,
            Self::InvalidChallenge => Severity::Warning,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::LockAcquireError(_))
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::LockFileError(_) => "Failed to create VDF lock file.".to_string(),
            Self::LockAcquireError(_) => "Failed to acquire VDF lock.".to_string(),
            Self::DiscriminantError => "Failed to create VDF discriminant.".to_string(),
            Self::ProofGenerationError => "Failed to generate VDF proof.".to_string(),
            Self::UnsupportedPlatform => {
                "VDF operations are not supported on this platform.".to_string()
            }
            Self::InvalidProof => "The VDF proof is structurally invalid or too large.".to_string(),
            Self::InvalidChallenge => {
                "The VDF challenge is degenerate and cannot be safely evaluated.".to_string()
            }
        }
    }
}
