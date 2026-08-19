//! Verifiable Delay Function (VDF) commitments, reveal payloads, and proof models.
//!
//! This module imports the core cryptographic types from `kinetic_verify` and
//! provides network-specific validation logic for domain names.

use super::names::is_valid_apex_name;
pub use kinetic_verify::{
    CommitRequest, Commitment, MAX_PAYLOAD_SIZE, PreviousProof, RESQUARING_EPOCH_KYNS, Reveal,
    VdfProof,
};

/// Extension trait providing network-specific validation logic for Reveal payloads.
pub trait RevealExt {
    /// Validates the reveal payload structure against protocol rules.
    fn validate(&self) -> Result<(), crate::error::KineticError>;
}

impl RevealExt for Reveal {
    /// Validates the reveal payload structure against protocol rules.
    ///
    /// # Errors
    ///
    /// - Returns [`crate::error::KineticError::Internal`] if `protocol_version != 1`.
    /// - Returns [`crate::error::KineticError::InvalidName`] (wrapping [`crate::error::NamesError`]) if the domain fails apex validation rules.
    /// - Returns [`crate::error::KineticError::Internal`] if the payload size exceeds `MAX_PAYLOAD_SIZE`.
    fn validate(&self) -> Result<(), crate::error::KineticError> {
        if self.protocol_version != 1 {
            return Err(crate::error::KineticError::Internal(format!(
                "Invalid protocol version {}. Only protocol version 1 is supported.",
                self.protocol_version
            )));
        }

        is_valid_apex_name(&self.name)?;

        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(crate::error::KineticError::Internal(format!(
                "Payload size {} exceeds MAX_PAYLOAD_SIZE {}",
                self.payload.len(),
                MAX_PAYLOAD_SIZE
            )));
        }

        if self.drand_signature.len() != 192 {
            return Err(crate::error::KineticError::Internal(format!(
                "Invalid drand_signature length: expected 192, got {}",
                self.drand_signature.len()
            )));
        }

        if self.pubkey.len() != 1952 {
            return Err(crate::error::KineticError::Internal(format!(
                "Invalid pubkey length: expected 1952, got {}",
                self.pubkey.len()
            )));
        }

        if self.signature.len() != 4627 {
            return Err(crate::error::KineticError::Internal(format!(
                "Invalid signature length: expected 4627, got {}",
                self.signature.len()
            )));
        }

        if self.vdf_proof.proof_bytes.len() > 2048 {
            return Err(crate::error::KineticError::Internal(format!(
                "VDF proof size {} exceeds maximum 2048",
                self.vdf_proof.proof_bytes.len()
            )));
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
            vdf_proof: VdfProof { proof_bytes: vec![0u8; 100] },
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
        assert!(reveal.validate().is_err());
    }

    #[test]
    fn test_invalid_name() {
        let mut reveal = valid_reveal();
        reveal.name = "invalid_name!".to_string();
        assert!(reveal.validate().is_err());
    }

    #[test]
    fn test_payload_too_large() {
        let mut reveal = valid_reveal();
        reveal.payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        assert!(reveal.validate().is_err());
    }

    #[test]
    fn test_invalid_drand_signature_length() {
        let mut reveal = valid_reveal();
        reveal.drand_signature = "a".repeat(191);
        assert!(reveal.validate().is_err());
        
        reveal.drand_signature = "a".repeat(193);
        assert!(reveal.validate().is_err());
    }

    #[test]
    fn test_invalid_pubkey_length() {
        let mut reveal = valid_reveal();
        reveal.pubkey = vec![0u8; 1951];
        assert!(reveal.validate().is_err());
    }

    #[test]
    fn test_invalid_signature_length() {
        let mut reveal = valid_reveal();
        reveal.signature = vec![0u8; 4626];
        assert!(reveal.validate().is_err());
    }

    #[test]
    fn test_vdf_proof_too_large() {
        let mut reveal = valid_reveal();
        reveal.vdf_proof.proof_bytes = vec![0u8; 2049];
        assert!(reveal.validate().is_err());
    }
}
