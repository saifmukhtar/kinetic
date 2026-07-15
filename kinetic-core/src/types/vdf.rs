use super::names::is_valid_apex_name;
use serde::{Deserialize, Serialize};

pub const RESQUARING_EPOCH_ROUNDS: u64 = 5_256_000; // ~6 months (182.5 days) at 3s/round
pub const MAX_PAYLOAD_SIZE: usize = 65_536;

/// Represents a cryptographic commitment to a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commitment {
    pub hash: [u8; 32],
}

/// Contains the bytes representing a Verifiable Delay Function (VDF) proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VdfProof {
    pub proof_bytes: Vec<u8>,
}

/// Request payload containing the name being registered and its commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRequest {
    pub name: String,
    pub commitment: Commitment,
}

fn default_protocol_version() -> u8 {
    2
}

/// Data for the previous VDF proof in a chain of proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviousProof {
    pub salt: [u8; 32],
    pub drand_pulse: u64,
    pub drand_randomness: String,
    pub iterations: u64,
    pub vdf_proof: VdfProof,
    pub signature: Vec<u8>,
}

impl PreviousProof {
    /// Serializes the previous proof data into a byte vector for hashing or signing.
    /// Returns the concatenated bytes of the proof parameters.
    pub fn proof_bytes(&self) -> Vec<u8> {
        let capacity = 32 // salt
            + 8 // drand_pulse
            + 4 + self.drand_randomness.len()
            + 8 // iterations
            + 4 + self.vdf_proof.proof_bytes.len()
            + 4 + self.signature.len();

        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.drand_pulse.to_be_bytes());

        bytes.extend_from_slice(&(self.drand_randomness.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.drand_randomness.as_bytes());

        bytes.extend_from_slice(&self.iterations.to_be_bytes());

        bytes.extend_from_slice(&(self.vdf_proof.proof_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.vdf_proof.proof_bytes);

        bytes.extend_from_slice(&(self.signature.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.signature);

        bytes
    }
}

/// Payload containing the revealed data for a commitment, including the VDF proof and signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reveal {
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u8,
    pub name: String,
    pub payload: Vec<u8>,
    pub salt: [u8; 32],
    pub drand_pulse: u64,
    pub drand_randomness: String,
    pub iterations: u64,
    pub vdf_proof: VdfProof,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub previous_proof: Option<PreviousProof>,
    pub miner_pubkey: Option<Vec<u8>>,
}

impl Reveal {
    /// Validates the reveal payload to ensure it conforms to protocol rules.
    ///
    /// # Errors
    ///
    /// Returns a `KineticError` if the protocol version is unsupported, the name is invalid, or the payload size exceeds `MAX_PAYLOAD_SIZE`.
    pub fn validate(&self) -> Result<(), crate::error::KineticError> {
        if self.protocol_version != 2 {
            return Err(crate::error::KineticError::Internal(format!(
                "Invalid protocol version {}. Only protocol version 2 is supported.",
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
        Ok(())
    }

    /// Serializes the reveal payload into a byte vector for cryptographic signing.
    /// Returns the length-prefixed serialized fields.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let prev_proof_bytes = self
            .previous_proof
            .as_ref()
            .map(|p| p.proof_bytes())
            .unwrap_or_default();

        // OPTIMIZATION: Calculate exact capacity to prevent multiple reallocations
        let mut capacity = 1 // protocol_version
            + 4 + self.name.len()
            + 4 + self.payload.len()
            + 32 // salt
            + 8 // drand_pulse
            + 4 + self.drand_randomness.len()
            + 8 // iterations
            + 4 + self.vdf_proof.proof_bytes.len()
            + 4 + self.pubkey.len()
            + 1; // previous_proof option flag

        if self.previous_proof.is_some() {
            capacity += 4 + prev_proof_bytes.len();
        }

        capacity += 1; // miner_pubkey option flag
        if let Some(miner_pk) = &self.miner_pubkey {
            capacity += 4 + miner_pk.len();
        }

        let mut bytes = Vec::with_capacity(capacity);
        bytes.push(self.protocol_version);

        // SECURITY: Length-prefix all variable-length fields (u32) to prevent canonicalization ambiguity attacks
        bytes.extend_from_slice(&(self.name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.name.as_bytes());

        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);

        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.drand_pulse.to_be_bytes());

        bytes.extend_from_slice(&(self.drand_randomness.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.drand_randomness.as_bytes());

        bytes.extend_from_slice(&self.iterations.to_be_bytes());

        bytes.extend_from_slice(&(self.vdf_proof.proof_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.vdf_proof.proof_bytes);

        bytes.extend_from_slice(&(self.pubkey.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.pubkey);

        if self.previous_proof.is_some() {
            bytes.push(1);
            bytes.extend_from_slice(&(prev_proof_bytes.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&prev_proof_bytes);
        } else {
            bytes.push(0);
        }

        if let Some(miner_pk) = &self.miner_pubkey {
            bytes.push(1);
            bytes.extend_from_slice(&(miner_pk.len() as u32).to_be_bytes());
            bytes.extend_from_slice(miner_pk);
        } else {
            bytes.push(0);
        }

        bytes
    }
}

/// Request parameters for initiating a new VDF computation job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdfJobRequest {
    pub challenge_hash: [u8; 32],
    pub name_length: u8,
    pub hashcash_nonce: u64,
    pub drand_pulse: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::TLD_SUFFIX;

    #[test]
    fn test_signable_bytes() {
        let reveal = Reveal {
            protocol_version: 2,
            name: format!("myname{}", TLD_SUFFIX),
            payload: vec![1, 2, 3],
            salt: [0u8; 32],
            drand_pulse: 100,
            drand_randomness: "randomness".to_string(),
            iterations: 1000,
            vdf_proof: VdfProof {
                proof_bytes: vec![4, 5, 6],
            },
            pubkey: vec![7, 8, 9],
            signature: vec![],
            previous_proof: None,
            miner_pubkey: None,
        };
        let bytes = reveal.signable_bytes();
        assert_eq!(bytes[0], 2);
        assert!(bytes.len() > 10);
    }
}
