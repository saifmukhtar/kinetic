//! Core governance data structures, action opcodes, and canonical binary serialization.
//!
//! Provides the data structures and binary parsing logic for privileged network actions
//! on the Kinetic network. This module is self-contained so that offline, air-gapped
//! key management and signing tools can construct, sign, and verify governance proposals
//! without pulling in network dependencies.
//!
//! ## Action Opcodes
//!
//! | Opcode | Action Variant | Description |
//! |---|---|---|
//! | `0x0A` | [`GovernanceAction::MapPrime`] | Grant a 1-character prime name (Root key only) |
//! | `0x0B` | [`GovernanceAction::RotateRootKey`] | Rotate network authority to a new ML-DSA-65 key |
//! | `0x0C` | [`GovernanceAction::EmergencyHalt`] | Emergency pause on registrations/renewals |
//! | `0x0D` | [`GovernanceAction::EmergencyResume`] | Resume registrations and advance pause offset |
//! | `0x0E` | [`GovernanceAction::UnmapPrime`] | Revoke a previously granted 1-character prime name |
//! | `0x0F` | [`GovernanceAction::MapInfra`] | Grant a Category 2 infrastructure name (Root key only) |
//! | `0x10` | [`GovernanceAction::UnmapInfra`] | Revoke a Category 2 infrastructure name (Root key only) |

use thiserror::Error;

/// 32-byte SHA-256 hash, used as action keys, veto targets, and proposal identifiers.
pub type Hash256 = [u8; 32];
/// Raw ML-DSA-65 public key bytes (typically 1952 bytes for ML-DSA-65).
pub type PublicKeyBytes = Vec<u8>;
/// Raw ML-DSA-65 signature bytes (typically 3309 bytes for ML-DSA-65).
pub type SignatureBytes = Vec<u8>;

/// Enumerates privileged protocol actions governed by network governance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GovernanceAction {
    /// Grant a 1-character premium name (Root key only).
    MapPrime {
        /// Target 1-character name label.
        name: String,
        /// Recipient's ML-DSA-65 public key.
        target_pubkey: PublicKeyBytes,
    },
    /// Revoke a 1-character premium name (Root key only).
    UnmapPrime {
        /// Target 1-character name label.
        name: String,
    },
    /// Grant a Category 2 network infrastructure name (Root key only).
    MapInfra {
        /// Target infrastructure name label (e.g., "seed", "api").
        name: String,
        /// Recipient's ML-DSA-65 public key.
        target_pubkey: PublicKeyBytes,
    },
    /// Revoke a Category 2 network infrastructure name (Root key only).
    UnmapInfra {
        /// Target infrastructure name label.
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
    EmergencyResume,
}

/// Proposal message container with signatures from authorized council members.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedGovernanceMessage {
    /// Target governance action payload.
    pub action: GovernanceAction,
    /// Unix timestamp in drand kyns when the proposal was signed.
    pub timestamp_kyn: u64,
    /// Array of ML-DSA-65 signatures.
    pub signatures: Vec<SignatureBytes>,
}

impl SignedGovernanceMessage {
    /// Serializes the governance message into a canonical byte vector for SHA-256 hashing and ML-DSA-65 signature verification.
    ///
    /// Each [`GovernanceAction`] variant is prefixed with a 1-byte opcode:
    ///
    /// | Opcode | Action Variant |
    /// |---|---|
    /// | `0x0A` | `MapPrime` |
    /// | `0x0B` | `RotateRootKey` |
    /// | `0x0C` | `EmergencyHalt` |
    /// | `0x0D` | `EmergencyResume` |
    /// | `0x0E` | `UnmapPrime` |
    /// | `0x0F` | `MapInfra` |
    /// | `0x10` | `UnmapInfra` |
    ///
    /// After the action payload, length-prefixed signatures (using a simple 1-byte count + N x 3309 bytes arrays) are written.
    /// The message closes with `u64_be(timestamp_kyn)`.
    ///
    /// # Returns
    ///
    /// A deterministic `Vec<u8>` suitable for SHA-256 hashing to derive the action hash,
    /// or for ML-DSA-65 signature verification.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match &self.action {
            GovernanceAction::MapPrime {
                name,
                target_pubkey,
            } => {
                buf.push(0x0A);
                let name_bytes = name.as_bytes();
                buf.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(name_bytes);
                buf.extend_from_slice(target_pubkey.as_slice());
            }
            GovernanceAction::UnmapPrime { name } => {
                buf.push(0x0E);
                let name_bytes = name.as_bytes();
                buf.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(name_bytes);
            }
            GovernanceAction::MapInfra {
                name,
                target_pubkey,
            } => {
                buf.push(0x0F);
                let name_bytes = name.as_bytes();
                buf.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(name_bytes);
                buf.extend_from_slice(target_pubkey.as_slice());
            }
            GovernanceAction::UnmapInfra { name } => {
                buf.push(0x10);
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
            GovernanceAction::EmergencyResume => {
                buf.push(0x0D);
            }
        }

        buf.extend_from_slice(&self.timestamp_kyn.to_be_bytes());
        buf
    }
}

/// Errors arising from canonical governance message parsing and validation.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum GovernanceTypeError {
    /// Provided byte slice is shorter than the minimum expected header or field size.
    #[error("Buffer too small for parsing governance payload")]
    BufferTooSmall,
    /// Opcode byte does not match any recognized governance action.
    #[error("Unknown governance opcode: 0x{0:02X}")]
    UnknownOpcode(u8),
    /// Name string field contains invalid UTF-8 bytes.
    #[error("Invalid UTF-8 sequence in premium name string")]
    InvalidUtf8,
    /// Provided public key length does not match expected ML-DSA-65 parameter size.
    #[error("Invalid public key length, expected 1952 bytes for ML-DSA-65")]
    InvalidPubkeyLength,
}

impl GovernanceAction {
    /// Parses a [`GovernanceAction`] and its trailing timestamp from a canonical byte slice.
    ///
    /// The canonical binary format consists of:
    /// - 1 byte opcode
    /// - Opcode-specific variable-length payload
    /// - 8 bytes timestamp (`u64` big-endian) at the very end
    pub fn parse_payload(bytes: &[u8]) -> Result<(Self, u64), GovernanceTypeError> {
        if bytes.len() < 9 {
            // At least 1 byte opcode + 8 bytes timestamp
            return Err(GovernanceTypeError::BufferTooSmall);
        }

        let timestamp_bytes = &bytes[bytes.len() - 8..];
        let timestamp_kyn = u64::from_be_bytes(timestamp_bytes.try_into().unwrap());
        let payload = &bytes[0..bytes.len() - 8];
        if payload.is_empty() {
            return Err(GovernanceTypeError::BufferTooSmall);
        }

        let opcode = payload[0];
        let action_data = &payload[1..];

        let action = match opcode {
            0x0A => {
                // MapPrime
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
                if pubkey_bytes.len() != 1952 {
                    return Err(GovernanceTypeError::InvalidPubkeyLength);
                }
                GovernanceAction::MapPrime {
                    name,
                    target_pubkey: pubkey_bytes.to_vec(),
                }
            }
            0x0B => {
                // RotateRootKey
                if action_data.len() != 1952 {
                    return Err(GovernanceTypeError::InvalidPubkeyLength);
                }
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
                GovernanceAction::EmergencyResume
            }
            0x0E => {
                // UnmapPrime
                if action_data.len() < 4 {
                    return Err(GovernanceTypeError::BufferTooSmall);
                }
                let name_len = u32::from_be_bytes(action_data[0..4].try_into().unwrap()) as usize;
                if action_data.len() < 4 + name_len {
                    return Err(GovernanceTypeError::BufferTooSmall);
                }
                let name = String::from_utf8(action_data[4..4 + name_len].to_vec())
                    .map_err(|_| GovernanceTypeError::InvalidUtf8)?;

                GovernanceAction::UnmapPrime { name }
            }
            0x0F => {
                // MapInfra
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
                if pubkey_bytes.len() != 1952 {
                    return Err(GovernanceTypeError::InvalidPubkeyLength);
                }
                GovernanceAction::MapInfra {
                    name,
                    target_pubkey: pubkey_bytes.to_vec(),
                }
            }
            0x10 => {
                // UnmapInfra
                if action_data.len() < 4 {
                    return Err(GovernanceTypeError::BufferTooSmall);
                }
                let name_len = u32::from_be_bytes(action_data[0..4].try_into().unwrap()) as usize;
                if action_data.len() < 4 + name_len {
                    return Err(GovernanceTypeError::BufferTooSmall);
                }
                let name = String::from_utf8(action_data[4..4 + name_len].to_vec())
                    .map_err(|_| GovernanceTypeError::InvalidUtf8)?;

                GovernanceAction::UnmapInfra { name }
            }
            _ => return Err(GovernanceTypeError::UnknownOpcode(opcode)),
        };

        Ok((action, timestamp_kyn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_parse_invalid_opcode() {
        // Opcode 0xFF is not a valid governance action
        let mut buf = vec![0xFF];
        buf.extend_from_slice(&[0; 8]); // Dummy timestamp
        let result = GovernanceAction::parse_payload(&buf);
        assert_eq!(result, Err(GovernanceTypeError::UnknownOpcode(0xFF)));
    }

    #[test]
    fn test_truncated_buffers() {
        // Buffer < 9 bytes should fail
        let buf = vec![0x0A, 0, 0, 0, 0, 0, 0, 0]; // 8 bytes
        assert_eq!(
            GovernanceAction::parse_payload(&buf),
            Err(GovernanceTypeError::BufferTooSmall)
        );

        let buf = vec![]; // 0 bytes
        assert_eq!(
            GovernanceAction::parse_payload(&buf),
            Err(GovernanceTypeError::BufferTooSmall)
        );
    }

    #[test]
    fn test_invalid_pubkey_length() {
        let name = "s";
        let mut buf = vec![0x0A];
        buf.extend_from_slice(&(name.len() as u32).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());

        // 3-byte public key (invalid)
        buf.extend_from_slice(&[1, 2, 3]);
        buf.extend_from_slice(&[0; 8]); // Timestamp

        let result = GovernanceAction::parse_payload(&buf);
        assert_eq!(result, Err(GovernanceTypeError::InvalidPubkeyLength));
    }

    #[test]
    fn test_invalid_utf8_name() {
        let mut buf = vec![0x0A];
        let bad_name: &[u8] = &[0xFF, 0xFE]; // Invalid UTF-8
        buf.extend_from_slice(&(bad_name.len() as u32).to_be_bytes());
        buf.extend_from_slice(bad_name);
        buf.extend_from_slice(&[0; 1952]); // Valid pubkey length
        buf.extend_from_slice(&[0; 8]); // Timestamp

        let result = GovernanceAction::parse_payload(&buf);
        assert_eq!(result, Err(GovernanceTypeError::InvalidUtf8));
    }

    #[test]
    fn test_roundtrip_valid_map_prime() {
        let action = GovernanceAction::MapPrime {
            name: "x".to_string(),
            target_pubkey: vec![42; 1952],
        };
        let msg = SignedGovernanceMessage {
            action: action.clone(),
            timestamp_kyn: 123456,
            signatures: vec![],
        };

        let buf = msg.to_bytes();
        let (parsed_action, parsed_time) = GovernanceAction::parse_payload(&buf).unwrap();

        assert_eq!(parsed_action, action);
        assert_eq!(parsed_time, 123456);
    }

    proptest! {
        #[test]
        fn test_parse_random_garbage(
            raw_payload in any::<Vec<u8>>()
        ) {
            // Fuzzer guarantees this will not panic under any garbage P2P input
            let _ = GovernanceAction::parse_payload(&raw_payload);
        }
    }
}
