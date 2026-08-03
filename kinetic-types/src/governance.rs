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
//! | `0x0A` | [`GovernanceAction::GrantPremiumName`] | Grant a 1-character apex name (Root key only) |
//! | `0x0B` | [`GovernanceAction::RotateRootKey`] | Rotate network authority to a new ML-DSA-65 key |
//! | `0x0C` | [`GovernanceAction::EmergencyHalt`] | Emergency pause on registrations/renewals |
//! | `0x0D` | [`GovernanceAction::EmergencyResume`] | Resume registrations and advance pause offset |
//! | `0x0E` | [`GovernanceAction::RevokePremiumName`] | Revoke a previously granted 1-character apex name |
//! | `0x0F` | [`GovernanceAction::GrantInfrastructureName`] | Grant a Category 2 infrastructure name (Root key only) |
//! | `0x10` | [`GovernanceAction::RevokeInfrastructureName`] | Revoke a Category 2 infrastructure name (Root key only) |

use crate::error::Severity;
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
    GrantPremiumName {
        /// Target 1-character name label.
        name: String,
        /// Recipient's ML-DSA-65 public key.
        target_pubkey: PublicKeyBytes,
    },
    /// Revoke a 1-character premium name (Root key only).
    RevokePremiumName {
        /// Target 1-character name label.
        name: String,
    },
    /// Grant a Category 2 network infrastructure name (Root key only).
    GrantInfrastructureName {
        /// Target infrastructure name label (e.g., "seed", "api").
        name: String,
        /// Recipient's ML-DSA-65 public key.
        target_pubkey: PublicKeyBytes,
    },
    /// Revoke a Category 2 network infrastructure name (Root key only).
    RevokeInfrastructureName {
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
    EmergencyResume {
        /// The exact number of drand kyns the network was halted for.
        paused_kyns: u64,
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
    /// | `0x0F` | `GrantInfrastructureName` |
    /// | `0x10` | `RevokeInfrastructureName` |
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
            GovernanceAction::GrantInfrastructureName {
                name,
                target_pubkey,
            } => {
                buf.push(0x0F);
                let name_bytes = name.as_bytes();
                buf.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(name_bytes);
                buf.extend_from_slice(target_pubkey.as_slice());
            }
            GovernanceAction::RevokeInfrastructureName { name } => {
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
            GovernanceAction::EmergencyResume { paused_kyns } => {
                buf.push(0x0D);
                buf.extend_from_slice(&paused_kyns.to_be_bytes());
            }
        }

        buf.extend_from_slice(&self.timestamp_sec.to_be_bytes());
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

impl GovernanceTypeError {
    /// Protocol error code following the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::BufferTooSmall => "KIN-GOV-030",
            Self::UnknownOpcode(_) => "KIN-GOV-031",
            Self::InvalidUtf8 => "KIN-GOV-032",
            Self::InvalidPubkeyLength => "KIN-GOV-033",
        }
    }

    /// Severity level for logging and telemetry.
    pub fn severity(&self) -> Severity {
        match self {
            Self::BufferTooSmall | Self::InvalidUtf8 | Self::InvalidPubkeyLength => Severity::Warning,
            Self::UnknownOpcode(_) => Severity::Error,
        }
    }

    /// Whether this parsing error can be retried without modifying payload data.
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Clean, user-facing error message suitable for frontend display.
    pub fn user_message(&self) -> String {
        match self {
            Self::BufferTooSmall => {
                "The governance payload buffer is truncated or smaller than required.".to_string()
            }
            Self::UnknownOpcode(op) => {
                format!("The governance action opcode (0x{op:02X}) is unrecognized by this protocol version.")
            }
            Self::InvalidUtf8 => {
                "The governance proposal contains an invalid UTF-8 name label.".to_string()
            }
            Self::InvalidPubkeyLength => {
                "The governance public key length does not match the ML-DSA-65 parameter size.".to_string()
            }
        }
    }

    /// RFC 7807 problem details type URI.
    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.network/errors/{}", self.code())
    }
}

impl GovernanceAction {
    /// Parses a [`GovernanceAction`] and its trailing timestamp from a canonical byte slice.
    ///
    /// The canonical binary format consists of:
    /// - 1 byte opcode
    /// - Opcode-specific variable-length payload
    /// - 8 bytes timestamp (`u64` big-endian) at the very end
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
                let paused_kyns = u64::from_be_bytes(action_data[0..8].try_into().unwrap());
                GovernanceAction::EmergencyResume { paused_kyns }
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
            0x0F => {
                // GrantInfrastructureName
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
                GovernanceAction::GrantInfrastructureName {
                    name,
                    target_pubkey: pubkey_bytes.to_vec(),
                }
            }
            0x10 => {
                // RevokeInfrastructureName
                if action_data.len() < 4 {
                    return Err(GovernanceTypeError::BufferTooSmall);
                }
                let name_len = u32::from_be_bytes(action_data[0..4].try_into().unwrap()) as usize;
                if action_data.len() < 4 + name_len {
                    return Err(GovernanceTypeError::BufferTooSmall);
                }
                let name = String::from_utf8(action_data[4..4 + name_len].to_vec())
                    .map_err(|_| GovernanceTypeError::InvalidUtf8)?;

                GovernanceAction::RevokeInfrastructureName { name }
            }
            _ => return Err(GovernanceTypeError::UnknownOpcode(opcode)),
        };

        Ok((action, timestamp_sec))
    }
}
