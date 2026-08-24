//! Verifiable Delay Function (VDF) commitments, reveal payloads, and proof models.
//!
//! This module imports the core cryptographic types from `kinetic_verify` and
//! provides network-specific validation logic for domain names.

use super::names::is_valid_apex_name;
pub use kinetic_verify::{
    CommitRequest, Commitment, MAX_PAYLOAD_SIZE, PreviousProof, RESQUARING_EPOCH_KYNS, Reveal,
    VdfProof,
};

use crate::error::vdf::RevealValidationError;

/// Extension trait providing network-specific validation logic for Reveal payloads.
pub trait RevealExt {
    /// Validates the reveal payload structure against protocol rules.
    fn validate(&self) -> Result<(), RevealValidationError>;
}

impl RevealExt for Reveal {
    /// Validates the reveal payload structure against protocol rules.
    ///
    /// # Errors
    ///
    /// Returns specific [`RevealValidationError`] variants for any structural violation.
    fn validate(&self) -> Result<(), RevealValidationError> {
        if self.protocol_version != 1 {
            return Err(RevealValidationError::InvalidProtocolVersion(
                self.protocol_version,
            ));
        }

        is_valid_apex_name(&self.name)?;

        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(RevealValidationError::PayloadTooLarge(
                self.payload.len(),
                MAX_PAYLOAD_SIZE,
            ));
        }

        if self.drand_signature.len() != 192 {
            return Err(RevealValidationError::InvalidDrandSignatureLength(
                192,
                self.drand_signature.len(),
            ));
        }

        if self.pubkey.len() != 1952 {
            return Err(RevealValidationError::InvalidPubkeyLength(
                1952,
                self.pubkey.len(),
            ));
        }

        if self.signature.len() != 4627 {
            return Err(RevealValidationError::InvalidSignatureLength(
                4627,
                self.signature.len(),
            ));
        }

        if self.vdf_proof.proof_bytes.len() > 2048 {
            return Err(RevealValidationError::VdfProofTooLarge(
                self.vdf_proof.proof_bytes.len(),
                2048,
            ));
        }

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn valid_reveal() -> Reveal {
        Reveal {
            name: format!("{}{}", "satoshi", crate::constants::NSP_SUFFIX),
            pubkey: vec![0u8; 1952],
            payload: vec![0u8; 100],
            signature: vec![0u8; 4627],
            previous_proof: None,
            iterations: 1000,
            vdf_proof: VdfProof {
                proof_bytes: vec![0u8; 100],
            },
            drand_kyn: 1000,
            drand_signature: "a".repeat(192),
            salt: [0u8; 32],
            protocol_version: 1,
            authorization: None,
            miner_pubkey: None,
        }
    }

    #[test]
    fn test_valid_reveal_passes() {
        let reveal = valid_reveal();
        assert!(reveal.validate().is_ok());
    }

    #[test]
    fn test_invalid_protocol_version() {
        let mut reveal = valid_reveal();
        reveal.protocol_version = 2;
        assert!(matches!(
            reveal.validate().unwrap_err(),
            RevealValidationError::InvalidProtocolVersion(2)
        ));
    }

    #[test]
    fn test_invalid_name() {
        let mut reveal = valid_reveal();
        reveal.name = "invalid_name!".to_string();
        assert!(matches!(
            reveal.validate().unwrap_err(),
            RevealValidationError::InvalidName(_)
        ));
    }

    #[test]
    fn test_payload_too_large() {
        let mut reveal = valid_reveal();
        reveal.payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        assert!(matches!(
            reveal.validate().unwrap_err(),
            RevealValidationError::PayloadTooLarge(_, _)
        ));
    }

    #[test]
    fn test_invalid_drand_signature_length() {
        let mut reveal = valid_reveal();

        // Too short
        reveal.drand_signature = "a".repeat(191);
        assert!(matches!(
            reveal.validate().unwrap_err(),
            RevealValidationError::InvalidDrandSignatureLength(192, 191)
        ));

        // Too long
        reveal.drand_signature = "a".repeat(193);
        assert!(matches!(
            reveal.validate().unwrap_err(),
            RevealValidationError::InvalidDrandSignatureLength(192, 193)
        ));
    }

    #[test]
    fn test_invalid_pubkey_length() {
        let mut reveal = valid_reveal();

        // Too short
        reveal.pubkey = vec![0u8; 1951];
        assert!(matches!(
            reveal.validate().unwrap_err(),
            RevealValidationError::InvalidPubkeyLength(1952, 1951)
        ));

        // Too long
        reveal.pubkey = vec![0u8; 1953];
        assert!(matches!(
            reveal.validate().unwrap_err(),
            RevealValidationError::InvalidPubkeyLength(1952, 1953)
        ));
    }

    #[test]
    fn test_invalid_signature_length() {
        let mut reveal = valid_reveal();

        // Too short
        reveal.signature = vec![0u8; 4626];
        assert!(matches!(
            reveal.validate().unwrap_err(),
            RevealValidationError::InvalidSignatureLength(4627, 4626)
        ));

        // Too long
        reveal.signature = vec![0u8; 4628];
        assert!(matches!(
            reveal.validate().unwrap_err(),
            RevealValidationError::InvalidSignatureLength(4627, 4628)
        ));
    }

    #[test]
    fn test_vdf_proof_too_large() {
        let mut reveal = valid_reveal();
        reveal.vdf_proof.proof_bytes = vec![0u8; 2049];
        assert!(matches!(
            reveal.validate().unwrap_err(),
            RevealValidationError::VdfProofTooLarge(_, _)
        ));
    }
}
