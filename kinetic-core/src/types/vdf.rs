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

        if self.beacon_signature.len() != 192 {
            return Err(RevealValidationError::InvalidBeaconSignatureLength(
                192,
                self.beacon_signature.len(),
            ));
        }

        if self.pubkey.len() != kinetic_primitives::KINETIC_PUBKEY_LENGTH {
            return Err(RevealValidationError::InvalidPubkeyLength(
                kinetic_primitives::KINETIC_PUBKEY_LENGTH,
                self.pubkey.len(),
            ));
        }

        if self.identity_signature.len() != kinetic_primitives::KINETIC_SIGNATURE_LENGTH {
            return Err(RevealValidationError::InvalidSignatureLength(
                kinetic_primitives::KINETIC_SIGNATURE_LENGTH,
                self.identity_signature.len(),
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
            pubkey: kinetic_primitives::keypairs::IdentityPubKey(
                vec![0u8; kinetic_primitives::KINETIC_PUBKEY_LENGTH],
            ),
            payload: vec![0u8; 100],
            identity_signature: kinetic_primitives::keypairs::IdentitySignature(
                vec![0u8; kinetic_primitives::KINETIC_SIGNATURE_LENGTH],
            ),
            previous_proof: None,
            iterations: 1000,
            vdf_proof: VdfProof {
                proof_bytes: vec![0u8; 100],
            },
            kyn: kinetic_kyn::types::TargetKyn::from(1000),
            beacon_signature: "a".repeat(192),
            salt: [0u8; 32],
            protocol_version: 1,
            authorization: None,
        }
    }

    #[test]
    fn test_valid_reveal_passes() {
        let reveal = valid_reveal();
        assert!(reveal.validate().is_ok());
    }

    #[test]
    fn test_reveal_invalid_version() {
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
    fn test_invalid_beacon_signature_length() {
        let mut reveal = valid_reveal();

        // Too short
        reveal.beacon_signature = "a".repeat(191);
        assert!(matches!(
            reveal.validate().unwrap_err(),
            RevealValidationError::InvalidBeaconSignatureLength(192, 191)
        ));

        // Too long
        reveal.beacon_signature = "a".repeat(193);
        assert!(matches!(
            reveal.validate().unwrap_err(),
            RevealValidationError::InvalidBeaconSignatureLength(192, 193)
        ));
    }

    #[test]
    fn test_invalid_pubkey_length() {
        let mut reveal = valid_reveal();

        // Too short
        reveal.pubkey = kinetic_primitives::keypairs::IdentityPubKey(vec![
            0u8;
            kinetic_primitives::KINETIC_PUBKEY_LENGTH
                - 1
        ]);
        let err = reveal.validate().unwrap_err();
        assert_eq!(
            err,
            RevealValidationError::InvalidPubkeyLength(
                kinetic_primitives::KINETIC_PUBKEY_LENGTH,
                kinetic_primitives::KINETIC_PUBKEY_LENGTH - 1
            )
        );

        let mut invalid_reveal2 = reveal.clone();
        invalid_reveal2.pubkey = kinetic_primitives::keypairs::IdentityPubKey(vec![
            0u8;
            kinetic_primitives::KINETIC_PUBKEY_LENGTH
                + 1
        ]);
        let err2 = invalid_reveal2.validate().unwrap_err();
        assert_eq!(
            err2,
            RevealValidationError::InvalidPubkeyLength(
                kinetic_primitives::KINETIC_PUBKEY_LENGTH,
                kinetic_primitives::KINETIC_PUBKEY_LENGTH + 1
            )
        );
    }

    #[test]
    fn test_invalid_signature_length() {
        let mut reveal = valid_reveal();

        // Too short
        reveal.identity_signature = kinetic_primitives::keypairs::IdentitySignature(vec![
            0u8;
            kinetic_primitives::KINETIC_SIGNATURE_LENGTH
                - 1
        ]);
        let err = reveal.validate().unwrap_err();
        assert_eq!(
            err,
            RevealValidationError::InvalidSignatureLength(
                kinetic_primitives::KINETIC_SIGNATURE_LENGTH,
                kinetic_primitives::KINETIC_SIGNATURE_LENGTH - 1
            )
        );

        let mut invalid_reveal2 = reveal.clone();
        invalid_reveal2.identity_signature = kinetic_primitives::keypairs::IdentitySignature(vec![
            0u8;
            kinetic_primitives::KINETIC_SIGNATURE_LENGTH + 1
        ]);
        let err2 = invalid_reveal2.validate().unwrap_err();
        assert_eq!(
            err2,
            RevealValidationError::InvalidSignatureLength(
                kinetic_primitives::KINETIC_SIGNATURE_LENGTH,
                kinetic_primitives::KINETIC_SIGNATURE_LENGTH + 1
            )
        );
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
