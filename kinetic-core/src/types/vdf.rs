//! Verifiable Delay Function (VDF) commitments, reveal payloads, and proof models.
//!
//! This module imports the core cryptographic types from `kinetic_verify` and
//! provides network-specific validation logic for domain names.

use super::names::is_valid_apex_name;
pub use kinetic_verify::{
    CommitRequest, Commitment, PreviousProof, Reveal, VdfJobRequest, VdfProof, MAX_PAYLOAD_SIZE,
    RESQUARING_EPOCH_ROUNDS,
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
