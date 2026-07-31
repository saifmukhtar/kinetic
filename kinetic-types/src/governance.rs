//! Core governance data structures and canonical serialization.
//! This module is standalone so it can be imported by offline air-gapped tools.

/// 32-byte SHA-256 hash, used as action keys, veto targets, and proposal identifiers.
pub type Hash256 = [u8; 32];
/// Raw ML-DSA-65 public key bytes (typically 1952 bytes for ML-DSA-65).
pub type PublicKeyBytes = Vec<u8>;
/// Raw ML-DSA-65 signature bytes (typically 3309 bytes for ML-DSA-65).
pub type SignatureBytes = Vec<u8>;

/// Enumerates privileged protocol actions governed by network governance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GovernanceAction {
    /// Grant a 1-character premium domain name (Root key only).
    GrantPremiumName {
        /// Target 1-character name label.
        name: String,
        /// Recipient's ML-DSA-65 public key.
        target_pubkey: PublicKeyBytes,
    },
    /// Revoke a 1-character premium domain name (Root key only).
    RevokePremiumName {
        /// Target 1-character name label.
        name: String,
    },
    /// Permanently delegates root authority to a new ML-DSA-65 public key.
    RotateRootKey {
        /// The new ML-DSA-65 root public key.
        new_key: PublicKeyBytes,
    },
    /// Emergency pause for network registration and renewals.
    EmergencyHalt,
    /// Resume network registration and renewals, adding to the global pause offset.
    EmergencyResume {
        /// The exact number of drand rounds the network was halted for.
        paused_rounds: u64,
    },
}

/// Proposal message container with signatures from authorized council members.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedGovernanceMessage {
    /// Target governance action payload.
    pub action: GovernanceAction,
    /// Proposal creation Unix timestamp in seconds.
    pub timestamp_sec: u64,
    /// Collected ML-DSA-65 signatures supporting this proposal.
    pub signatures: Vec<SignatureBytes>,
}

impl SignedGovernanceMessage {
    /// Serializes the governance message into a canonical byte vector for SHA-256 hashing and ML-DSA-65 signature verification.
    ///
    /// Each [`GovernanceAction`] variant is prefixed with a 1-byte opcode:
    ///
    /// | Opcode | Action Variant |
    /// |---|---|
    /// | `0x0A` | `GrantPremiumName` |
    /// | `0x0B` | `RotateRootKey` |
    /// | `0x0C` | `EmergencyHalt` |
    /// | `0x0D` | `EmergencyResume` |
    /// | `0x0E` | `RevokePremiumName` |
    ///
    /// The message closes with `u64_be(timestamp_sec)`.
    ///
    /// # Returns
    ///
    /// A deterministic `Vec<u8>` suitable for SHA-256 hashing to derive the action hash,
    /// or for ML-DSA-65 signature verification.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match &self.action {
            GovernanceAction::GrantPremiumName {
                name,
                target_pubkey,
            } => {
                buf.push(0x0A);
                let name_bytes = name.as_bytes();
                buf.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(name_bytes);
                buf.extend_from_slice(target_pubkey.as_slice());
            }
            GovernanceAction::RevokePremiumName { name } => {
                buf.push(0x0E);
                let name_bytes = name.as_bytes();
                buf.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(name_bytes);
            }
            GovernanceAction::RotateRootKey { new_key } => {
                buf.push(0x0B);
                buf.extend_from_slice(new_key.as_slice());
            }
            GovernanceAction::EmergencyHalt => {
                buf.push(0x0C);
            }
            GovernanceAction::EmergencyResume { paused_rounds } => {
                buf.push(0x0D);
                buf.extend_from_slice(&paused_rounds.to_be_bytes());
            }
        }

        buf.extend_from_slice(&self.timestamp_sec.to_be_bytes());
        buf
    }
}

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum GovernanceTypeError {
    #[error("Buffer too small for parsing")]
    BufferTooSmall,
    #[error("Unknown governance opcode: {0}")]
    UnknownOpcode(u8),
    #[error("Invalid UTF-8 in premium name string")]
    InvalidUtf8,
    #[error("Invalid pubkey length, expected 1952 bytes")]
    InvalidPubkeyLength,
}

impl GovernanceAction {
    /// Parses a GovernanceAction and the appended timestamp from a canonical byte slice.
    ///
    /// The canonical format expects:
    /// - 1 byte opcode
    /// - Opcode-specific payload
    /// - 8 bytes timestamp (u64 big-endian) at the very end
    pub fn parse_canonical_payload(bytes: &[u8]) -> Result<(Self, u64), GovernanceTypeError> {
        if bytes.len() < 9 {
            // At least 1 byte opcode + 8 bytes timestamp
            return Err(GovernanceTypeError::BufferTooSmall);
        }

        let timestamp_bytes = &bytes[bytes.len() - 8..];
        let timestamp_sec = u64::from_be_bytes(timestamp_bytes.try_into().unwrap());
        
        let payload = &bytes[0..bytes.len() - 8];
        if payload.is_empty() {
            return Err(GovernanceTypeError::BufferTooSmall);
        }

        let opcode = payload[0];
        let action_data = &payload[1..];

        let action = match opcode {
            0x0A => {
                // GrantPremiumName
                if action_data.len() < 4 {
                    return Err(GovernanceTypeError::BufferTooSmall);
                }
                let name_len = u32::from_be_bytes(action_data[0..4].try_into().unwrap()) as usize;
                if action_data.len() < 4 + name_len {
                    return Err(GovernanceTypeError::BufferTooSmall);
                }
                let name = String::from_utf8(action_data[4..4 + name_len].to_vec())
                    .map_err(|_| GovernanceTypeError::InvalidUtf8)?;
                
                let pubkey_bytes = &action_data[4 + name_len..];
                // Note: ML-DSA-65 public keys are 1952 bytes, but we allow parsing any trailing bytes as the pubkey.
                // If strict validation is required, check length here.
                
                GovernanceAction::GrantPremiumName {
                    name,
                    target_pubkey: pubkey_bytes.to_vec(),
                }
            }
            0x0B => {
                // RotateRootKey
                GovernanceAction::RotateRootKey {
                    new_key: action_data.to_vec(),
                }
            }
            0x0C => {
                // EmergencyHalt
                GovernanceAction::EmergencyHalt
            }
            0x0D => {
                // EmergencyResume
                if action_data.len() < 8 {
                    return Err(GovernanceTypeError::BufferTooSmall);
                }
                let paused_rounds = u64::from_be_bytes(action_data[0..8].try_into().unwrap());
                GovernanceAction::EmergencyResume { paused_rounds }
            }
            0x0E => {
                // RevokePremiumName
                if action_data.len() < 4 {
                    return Err(GovernanceTypeError::BufferTooSmall);
                }
                let name_len = u32::from_be_bytes(action_data[0..4].try_into().unwrap()) as usize;
                if action_data.len() < 4 + name_len {
                    return Err(GovernanceTypeError::BufferTooSmall);
                }
                let name = String::from_utf8(action_data[4..4 + name_len].to_vec())
                    .map_err(|_| GovernanceTypeError::InvalidUtf8)?;
                
                GovernanceAction::RevokePremiumName { name }
            }
            _ => return Err(GovernanceTypeError::UnknownOpcode(opcode)),
        };

        Ok((action, timestamp_sec))
    }
}
