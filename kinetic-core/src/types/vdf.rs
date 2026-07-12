use serde::{Deserialize, Serialize};
use super::names::{is_valid_apex_name};

pub const RESQUARING_EPOCH_ROUNDS: u64 = 1_051_200;
pub const MAX_PAYLOAD_SIZE: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commitment {
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VdfProof {
    pub proof_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRequest {
    pub name: String,
    pub commitment: Commitment,
}

fn default_protocol_version() -> u8 {
    2
}

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
    pub fn proof_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.drand_pulse.to_be_bytes());
        bytes.extend_from_slice(self.drand_randomness.as_bytes());
        bytes.extend_from_slice(&self.iterations.to_be_bytes());
        bytes.extend_from_slice(&self.vdf_proof.proof_bytes);
        bytes.extend_from_slice(&self.signature);
        bytes
    }
}

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
    pub points_spent: Option<u64>,
}

impl Reveal {
    pub fn validate(&self) -> Result<(), crate::error::KineticError> {
        if self.protocol_version != 2 {
            return Err(crate::error::KineticError::Internal(format!(
                "Invalid protocol version {}. Only protocol version 2 is supported.",
                self.protocol_version
            )));
        }

        if !is_valid_apex_name(&self.name) {
            return Err(crate::error::KineticError::Internal(format!(
                "Invalid name '{}'. Only apex domains are allowed.",
                self.name
            )));
        }

        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(crate::error::KineticError::Internal(format!(
                "Payload size {} exceeds MAX_PAYLOAD_SIZE {}",
                self.payload.len(),
                MAX_PAYLOAD_SIZE
            )));
        }
        Ok(())
    }

    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.protocol_version);
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.drand_pulse.to_be_bytes());
        bytes.extend_from_slice(self.drand_randomness.as_bytes());
        bytes.extend_from_slice(&self.iterations.to_be_bytes());
        bytes.extend_from_slice(&self.vdf_proof.proof_bytes);
        bytes.extend_from_slice(&self.pubkey);

        if let Some(prev) = &self.previous_proof {
            bytes.extend_from_slice(&prev.proof_bytes());
        }
        if let Some(miner_pk) = &self.miner_pubkey {
            bytes.extend_from_slice(miner_pk);
        }
        if let Some(points) = self.points_spent {
            bytes.extend_from_slice(&points.to_be_bytes());
        }

        bytes
    }
}

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
    use super::super::names::DOT_TLD;

    #[test]
    fn test_signable_bytes() {
        let reveal = Reveal {
            protocol_version: 2,
            name: format!("{}{}", "test", DOT_TLD),
            payload: vec![1, 2, 3],
            salt: [0u8; 32],
            drand_pulse: 100,
            drand_randomness: "randomness".to_string(),
            iterations: 1000,
            vdf_proof: VdfProof { proof_bytes: vec![4, 5, 6] },
            pubkey: vec![7, 8, 9],
            signature: vec![],
            previous_proof: None,
            miner_pubkey: None,
            points_spent: None,
        };
        let bytes = reveal.signable_bytes();
        assert_eq!(bytes[0], 2);
        assert!(bytes.len() > 10);
    }
}
