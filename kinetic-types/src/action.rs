//! Core action data structures, action opcodes, and canonical binary serialization.
//!
//! Provides the data structures and binary parsing logic for privileged network actions
//! on the Kinetic network. This module is self-contained so that offline, air-gapped
//! key management and signing tools can construct, sign, and verify action proposals
//! without pulling in network dependencies.
//!
//! ## Action Opcodes
//!
//! | Opcode | Action Variant | Description |
//! |---|---|---|
//! | `0x0B` | [`NetworkAction::RotateSovereignKey`] | Rotate network authority to a new Sovereign key |
//! | `0x0C` | [`NetworkAction::EmergencyHalt`] | Emergency pause on registrations/renewals |
//! | `0x0D` | [`NetworkAction::EmergencyResume`] | Resume registrations and advance pause offset |


use kinetic_primitives::keypairs::SovereignPubKey;
use thiserror::Error;

/// 32-byte SHA-256 hash, used as action keys, veto targets, and proposal identifiers.
pub type Hash256 = [u8; 32];

/// Raw Sovereign key signature bytes.
///
/// # Security
/// The network currently strictly expects the ML-DSA-65 signature output 
/// of the underlying Sovereign key algorithm.
pub type SovereignSignature = Vec<u8>;

/// Enumerates privileged protocol actions managed by the network action system.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NetworkAction {
    /// Permanently delegates Sovereign authority to a new Sovereign public key.
    RotateSovereignKey {
        /// The new strictly-typed Sovereign public key.
        #[serde(with = "crate::pubkey_serde::sovereign_serde")]
        new_key: SovereignPubKey,
    },
    /// Emergency pause for network registration and renewals.
    EmergencyHalt,
    /// Resume network registration and renewals, adding to the global pause offset.
    EmergencyResume,
}

/// Proposal message container with signatures from authorized council members.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedNetworkAction {
    /// Target network action payload.
    pub action: NetworkAction,
    /// Network timestamp in drand kyns when the proposal was signed.
    pub timestamp_kyn: kinetic_kyn::types::TimestampKyn,
    /// The Sovereign signatures authorizing this action.
    pub sovereign_signatures: Vec<SovereignSignature>,
}

impl SignedNetworkAction {
    /// Serializes the action message into a canonical byte vector for SHA-256 hashing and Sovereign signature verification.
    ///
    /// Each [`NetworkAction`] variant is prefixed with a 1-byte opcode:
    ///
    /// | Opcode | Action Variant |
    /// |---|---|
    /// | `0x0B` | `RotateSovereignKey` |
    /// | `0x0C` | `EmergencyHalt` |
    /// | `0x0D` | `EmergencyResume` |

    ///
    /// After the action payload, length-prefixed signatures (using a simple 1-byte count + N x KINETIC_SIGNATURE_LENGTH bytes arrays) are written.
    /// The message closes with `u64_be(timestamp_kyn)`.
    ///
    /// # Returns
    ///
    /// A deterministic `Vec<u8>` suitable for SHA-256 hashing to derive the action hash,
    /// or for Sovereign signature verification.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match &self.action {
            NetworkAction::RotateSovereignKey { new_key } => {
                buf.push(0x0B);
                buf.extend_from_slice(new_key.as_bytes());
            }
            NetworkAction::EmergencyHalt => {
                buf.push(0x0C);
            }
            NetworkAction::EmergencyResume => {
                buf.push(0x0D);
            }
        }

        buf.extend_from_slice(&self.timestamp_kyn.to_be_bytes());
        buf
    }
}

/// Errors arising from canonical action message parsing and validation.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ActionParseError {
    /// Provided byte slice is shorter than the minimum expected header or field size.
    #[error("Buffer too small for parsing action payload")]
    BufferTooSmall,
    /// Opcode byte does not match any recognized action action.
    #[error("Unknown action opcode: 0x{0:02X}")]
    UnknownOpcode(u8),

    /// Provided public key length does not match expected parameter size.
    #[error("Invalid public key length, expected KINETIC_PUBKEY_LENGTH bytes")]
    InvalidPubkeyLength,
}

impl NetworkAction {
    /// Parses a [`NetworkAction`] and its trailing timestamp from a canonical byte slice.
    ///
    /// The canonical binary format consists of:
    /// - 1 byte opcode
    /// - Opcode-specific variable-length payload
    /// - 8 bytes timestamp (`u64` big-endian) at the very end
    ///
    /// # Security
    /// This parser is fuzz-tested to ensure it never panics on malformed P2P network input.
    /// It enforces strict bounds checking (e.g., public keys must be exactly KINETIC_PUBKEY_LENGTH bytes).
    ///
    /// # Errors
    /// - Returns [`ActionParseError::BufferTooSmall`] if the buffer is under 9 bytes.
    /// - Returns [`ActionParseError::UnknownOpcode`] if the action variant is unrecognized.
    /// - Returns [`ActionParseError::InvalidPubkeyLength`] if a parsed key does not meet strict byte bounds.
    ///
    /// # Examples
    /// ```rust
    /// use kinetic_types::action::{NetworkAction, ActionParseError};
    /// 
    /// // A buffer that is too small (8 bytes total)
    /// let bad_buf = vec![0x0F, 0, 0, 0, 0, 0, 0, 0];
    /// assert_eq!(
    ///     NetworkAction::parse_payload(&bad_buf),
    ///     Err(ActionParseError::BufferTooSmall)
    /// );
    /// ```
    pub fn parse_payload(bytes: &[u8]) -> Result<(Self, kinetic_kyn::types::Kyn), ActionParseError> {
        if bytes.len() < 9 {
            // At least 1 byte opcode + 8 bytes timestamp
            return Err(ActionParseError::BufferTooSmall);
        }

        let timestamp_bytes = &bytes[bytes.len() - 8..];
        let timestamp_kyn = kinetic_kyn::types::Kyn::from_be_bytes(timestamp_bytes.try_into().unwrap());
        let payload = &bytes[0..bytes.len() - 8];
        if payload.is_empty() {
            return Err(ActionParseError::BufferTooSmall);
        }

        let opcode = payload[0];
        let action_data = &payload[1..];

        let action = match opcode {
            0x0B => {
                // RotateSovereignKey
                if action_data.len() != kinetic_primitives::KINETIC_PUBKEY_LENGTH {
                    return Err(ActionParseError::InvalidPubkeyLength);
                }
                NetworkAction::RotateSovereignKey {
                    new_key: SovereignPubKey(action_data.to_vec()),
                }
            }
            0x0C => {
                // EmergencyHalt
                NetworkAction::EmergencyHalt
            }
            0x0D => {
                // EmergencyResume
                NetworkAction::EmergencyResume
            }

            _ => return Err(ActionParseError::UnknownOpcode(opcode)),
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
        // Opcode 0xFF is not a valid action action
        let mut buf = vec![0xFF];
        buf.extend_from_slice(&[0; 8]); // Placeholder timestamp
        let result = NetworkAction::parse_payload(&buf);
        assert_eq!(result, Err(ActionParseError::UnknownOpcode(0xFF)));
    }

    #[test]
    fn test_truncated_buffers() {
        // Buffer < 9 bytes should fail
        let buf = vec![0x0F, 0, 0, 0, 0, 0, 0, 0]; // 8 bytes
        assert_eq!(
            NetworkAction::parse_payload(&buf),
            Err(ActionParseError::BufferTooSmall)
        );
    }

    #[test]
    fn test_parse_empty_payload_too_small() {
        let result = NetworkAction::parse_payload(&[]);
        assert_eq!(result, Err(ActionParseError::BufferTooSmall));
    }

    #[test]
    fn test_invalid_pubkey_length() {
        let mut buf = vec![0x0B];
        // 3-byte public key (invalid)
        buf.extend_from_slice(&[1, 2, 3]);
        buf.extend_from_slice(&[0; 8]); // Timestamp

        let result = NetworkAction::parse_payload(&buf);
        assert_eq!(result, Err(ActionParseError::InvalidPubkeyLength));
    }





    proptest! {
        #[test]
        fn test_parse_random_bytes(
            raw_payload in any::<Vec<u8>>()
        ) {
            // Fuzzer guarantees this will not panic under any malformed P2P input
            let _ = NetworkAction::parse_payload(&raw_payload);
        }
    }
}

/// Request to sync historical action actions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionSyncRequest {
    /// Request missed action messages starting from this Kyn index.
    pub from_kyn: kinetic_kyn::types::Kyn,
}

/// Response containing historical action actions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionSyncResponse {
    /// The append-only log of all executed signed action messages.
    pub actions: Vec<SignedNetworkAction>,
}
