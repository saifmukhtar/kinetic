//! Error types for the kinetic-verify crate.

use kinetic_types::error::Severity;
use thiserror::Error;

/// Errors arising from ML-DSA-65 post-quantum signature verification on VDF reveal and name payloads.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignatureVerifyError {
    /// Provided public key bytes could not be parsed into a valid ML-DSA-65 verifying key.
    #[error("Malformed ML-DSA-65 public key")]
    MalformedPublicKey,
    /// Signature byte slice does not conform to the ML-DSA-65 signature structure.
    #[error("Malformed ML-DSA-65 signature bytes")]
    MalformedSignature,
    /// Cryptographic verification failed over the canonical signable bytes.
    #[error("Invalid ML-DSA-65 post-quantum signature")]
    InvalidSignature,
    /// The delegated manifest does not grant the required capability.
    #[error("Delegated capability missing from authorized manifest")]
    DelegatedCapabilityMissing,
    /// The delegated authorization proof is structurally invalid or fails signature check.
    #[error("Delegated authorization proof is invalid")]
    DelegatedAuthorizationInvalid,
    /// The delegated manifest name scope does not match the target name.
    #[error("Delegated manifest name scope does not match the target name")]
    DelegatedScopeViolation,
    /// The delegated manifest is missing the required KID document.
    #[error("Delegated manifest is missing the required KID document")]
    DelegatedKidDocumentMissing,
}

impl SignatureVerifyError {
    /// Protocol error code following the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MalformedPublicKey => "KIN-VDF-040",
            Self::MalformedSignature => "KIN-VDF-041",
            Self::InvalidSignature => "KIN-VDF-042",
            Self::DelegatedCapabilityMissing => "KIN-VDF-043",
            Self::DelegatedAuthorizationInvalid => "KIN-VDF-044",
            Self::DelegatedScopeViolation => "KIN-VDF-045",
            Self::DelegatedKidDocumentMissing => "KIN-VDF-046",
        }
    }

    /// Severity level for logging and telemetry.
    pub fn severity(&self) -> Severity {
        match self {
            Self::MalformedPublicKey | Self::MalformedSignature => Severity::Warning,
            Self::InvalidSignature
            | Self::DelegatedCapabilityMissing
            | Self::DelegatedAuthorizationInvalid
            | Self::DelegatedScopeViolation
            | Self::DelegatedKidDocumentMissing => Severity::Error,
        }
    }

    /// Whether this verification error can be retried without modifying inputs.
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Clean, user-facing error message suitable for frontend display.
    pub fn user_message(&self) -> String {
        match self {
            Self::MalformedPublicKey => {
                "The name owner's ML-DSA-65 public key is corrupted or invalid.".to_string()
            }
            Self::MalformedSignature => "The ML-DSA-65 signature format is malformed.".to_string(),
            Self::InvalidSignature => {
                "The post-quantum ownership signature failed cryptographic verification."
                    .to_string()
            }
            Self::DelegatedCapabilityMissing => {
                "The delegated manifest does not grant the required capability for this action."
                    .to_string()
            }
            Self::DelegatedAuthorizationInvalid => {
                "The delegated authorization proof could not be verified against the master key."
                    .to_string()
            }
            Self::DelegatedScopeViolation => {
                "The delegated manifest is locked to a different name and cannot be used here."
                    .to_string()
            }
            Self::DelegatedKidDocumentMissing => {
                "The delegated authorization payload is missing its required KID document."
                    .to_string()
            }
        }
    }

    /// RFC 7807 problem details type URI.
    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.network/errors/{}", self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_verify_error_taxonomy() {
        assert_eq!(SignatureVerifyError::DelegatedScopeViolation.code(), "KIN-VDF-045");
        assert_eq!(SignatureVerifyError::DelegatedScopeViolation.severity(), Severity::Error);
        assert!(!SignatureVerifyError::DelegatedScopeViolation.is_retryable());

        assert_eq!(SignatureVerifyError::DelegatedKidDocumentMissing.code(), "KIN-VDF-046");
        assert_eq!(SignatureVerifyError::DelegatedKidDocumentMissing.severity(), Severity::Error);
        assert!(!SignatureVerifyError::DelegatedKidDocumentMissing.is_retryable());
    }
}
