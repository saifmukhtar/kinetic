//! Error types for the kinetic-verify crate.

use kinetic_types::error::Severity;
use thiserror::Error;

/// Errors arising from ML-DSA-65 post-quantum signature verification on VDF reveal and name payloads.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignatureVerifyError {
    /// Malformed Public Key. The provided byte array is not a valid ML-DSA-65 public key.
    /// The public key may be truncated, corrupted, or formatted for a different cryptographic scheme.
    /// Ensure the key is exactly the length required by ML-DSA-65 and generated correctly.
    #[error("Malformed ML-DSA-65 public key")]
    MalformedPublicKey,
    /// Malformed Signature. The signature byte slice does not conform to the ML-DSA-65 signature structure.
    /// The signature may have been truncated during network transmission or storage.
    /// Ensure the signature is exactly the length required by ML-DSA-65.
    #[error("Malformed ML-DSA-65 signature bytes")]
    MalformedSignature,
    /// Invalid Signature. Cryptographic verification failed over the canonical signable bytes.
    /// The payload was either tampered with in transit, or it was signed with the wrong private key.
    /// Ensure you are signing the exact canonical JSON payload with the correct identity key.
    #[error("Invalid ML-DSA-65 post-quantum signature")]
    InvalidSignature,
    /// Delegated Capability Missing. The delegated manifest does not grant the required capability.
    /// An entity attempted an action (like publishing a record) without the correct capability listed in the manifest.
    /// The apex owner must update the manifest to explicitly grant this capability.
    #[error("Delegated capability missing from authorized manifest")]
    DelegatedCapabilityMissing,
    /// Delegated Authorization Invalid. The delegated authorization proof is structurally invalid or fails signature check.
    /// The proof chain linking the delegate to the apex owner is broken or cryptographically forged.
    /// Ensure the delegate was actually authorized by the current apex owner.
    #[error("Delegated authorization proof is invalid")]
    DelegatedAuthorizationInvalid,
    /// Delegated Scope Violation. The delegated manifest name scope does not match the target name.
    /// A delegate attempted to perform an action on a name they are not authorized to manage.
    /// Double check the domain name in the manifest matches the target resource exactly.
    #[error("Delegated manifest name scope does not match the target name")]
    DelegatedScopeViolation,
    /// Delegated KID Document Missing. The delegated manifest is missing the required KID document.
    /// In order to verify the delegation chain, the apex owner's identity document must be included.
    /// Include the full, signed KID document in the delegated request.
    #[error("Delegated manifest is missing the required KID document")]
    DelegatedKidDocumentMissing,
}

impl SignatureVerifyError {
    /// Protocol error code following the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MalformedPublicKey => "KIN-VER-001",
            Self::MalformedSignature => "KIN-VER-002",
            Self::InvalidSignature => "KIN-VER-003",
            Self::DelegatedCapabilityMissing => "KIN-VER-004",
            Self::DelegatedAuthorizationInvalid => "KIN-VER-005",
            Self::DelegatedScopeViolation => "KIN-VER-006",
            Self::DelegatedKidDocumentMissing => "KIN-VER-007",
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
        assert_eq!(
            SignatureVerifyError::DelegatedScopeViolation.code(),
            "KIN-VER-006"
        );
        assert_eq!(
            SignatureVerifyError::DelegatedScopeViolation.severity(),
            Severity::Error
        );
        assert!(!SignatureVerifyError::DelegatedScopeViolation.is_retryable());

        assert_eq!(
            SignatureVerifyError::DelegatedKidDocumentMissing.code(),
            "KIN-VER-007"
        );
        assert_eq!(
            SignatureVerifyError::DelegatedKidDocumentMissing.severity(),
            Severity::Error
        );
        assert!(!SignatureVerifyError::DelegatedKidDocumentMissing.is_retryable());
    }
}
