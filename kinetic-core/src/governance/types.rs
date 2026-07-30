//! Data structures and serialized action types for network governance.
//!
//! Defines the complete set of [`GovernanceAction`] variants, the persistent [`GovernanceState`],
//! the [`SignedGovernanceMessage`] proposal envelope, and canonical byte serialization.
//!
//! ## Protocol Context
//!
//! All governance state changes follow a two-phase commit protocol:
//! 1. A [`SignedGovernanceMessage`] is broadcast with one or more ML-DSA-65 signatures.
//! 2. Threshold verification by the active [`GovernanceEngine`](crate::traits::GovernanceEngine)
//!    determines whether the action is immediately executed or enters a timelock queue.
//!
//! In **Founder mode** ([`GovernanceMode::Founder`]), the Root key acts as single-signer authority
//! (no council threshold required). The `LockCouncil` action permanently transitions the network
//! to **Council mode** ([`GovernanceMode::Council`]), after which Root key authority is removed.

use ml_dsa::signature::Verifier;
use ml_dsa::KeyInit;
use ml_dsa::MlDsa65;
use std::collections::{HashMap, HashSet};

/// 32-byte SHA-256 hash, used as action keys, veto targets, and proposal identifiers.
pub type Hash256 = [u8; 32];
/// Raw ML-DSA-65 public key bytes (typically 1952 bytes for ML-DSA-65).
pub type PublicKeyBytes = Vec<u8>;
/// Raw ML-DSA-65 signature bytes (typically 3309 bytes for ML-DSA-65).
pub type SignatureBytes = Vec<u8>;

/// Verifies an ML-DSA-65 post-quantum signature over a message byte slice.
///
/// # Security
///
/// Returns `true` if the signature is cryptographically valid for `pubkey`; `false` if key decoding,
/// signature parsing, or verification fails.
pub fn verify_signature(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if let Ok(pk) = ml_dsa::VerifyingKey::<MlDsa65>::new_from_slice(pubkey) {
        if let Ok(signature) = ml_dsa::Signature::<MlDsa65>::try_from(sig) {
            return pk.verify(msg, &signature).is_ok();
        }
    }
    false
}

/// Enumerates privileged protocol actions governed by council threshold voting or Founder mode.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum GovernanceAction {
    /// Appoint a new member key to the network Council.
    AppointMember {
        /// ML-DSA-65 public key of the candidate member.
        key: PublicKeyBytes,
    },

    /// Transition the network from Founder mode to Council mode.
    LockCouncil,

    /// Rotate the network's offline Root public key.
    RotateRootKey {
        /// New ML-DSA-65 Root public key.
        new_key: PublicKeyBytes,
    },
    /// Rotate an existing council member's signing key.
    RotateCouncilMemberKey {
        /// Existing public key of the member.
        target_key: PublicKeyBytes,
        /// Replacement public key of the member.
        new_key: PublicKeyBytes,
    },
    /// Remove an active member from the network Council.
    RemoveCouncilMember {
        /// Public key of the member to remove.
        target_key: PublicKeyBytes,
    },

    /// Grant a 1-character premium domain name (Founder phase only, max 5 lifetime grants).
    GrantPremiumName {
        /// Target 1-character name label.
        name: String,
        /// Recipient's ML-DSA-65 public key.
        target_pubkey: PublicKeyBytes,
    },
}

/// Side effects produced when a governance action is executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceEffect {

    /// Inform node subsystems of a premium domain grant.
    PremiumNameGranted {
        /// Granted 1-character name.
        name: String,
        /// Recipient public key.
        target_pubkey: PublicKeyBytes,
    },
}

/// Operational governance mode of the network.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GovernanceMode {
    /// Founder bootstrap mode: initial root key holds single-signer ratification authority.
    Founder,
    /// Decentralized Council mode: actions require supermajority threshold voting.
    Council,
}

/// Proposal message container with signatures from authorized council members.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedGovernanceMessage {
    /// Target governance action payload.
    pub action: GovernanceAction,
    /// Recorded council size at the time the proposal was created (prevents denominator manipulation).
    pub council_size_at_proposal: u32,
    /// Proposal creation Unix timestamp in seconds.
    pub timestamp_sec: u64,
    /// Collected ML-DSA-65 signatures supporting this proposal.
    pub signatures: Vec<SignatureBytes>,
}

/// Persistent on-disk state container for the network governance subsystem.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GovernanceState {
    /// Unix timestamp of network genesis.
    pub genesis_timestamp_sec: u64,
    /// Current operating mode ([`GovernanceMode::Founder`] vs [`GovernanceMode::Council`]).
    pub mode: GovernanceMode,
    /// Timestamp when Council mode was locked, if applicable.
    pub lock_timestamp_sec: Option<u64>,
    /// List of active council member public keys.
    pub active_council: Vec<PublicKeyBytes>,
    /// Map tracking the last signature timestamp per council member to detect inactive members.
    pub last_signature_timestamps: HashMap<PublicKeyBytes, u64>,
    /// Map of action hashes that have already been executed to their timestamp (prevents replay attacks).
    #[serde(default)]
    pub executed_hashes: HashMap<Hash256, u64>,

    /// In-progress proposals aggregating threshold signatures.
    pub partial_proposals: HashMap<Hash256, SignedGovernanceMessage>,
    /// Counter tracking 1-character premium name grants issued by the Founder (max 5).
    pub founder_premium_grants: u8,
    /// Start timestamp of the 14-day automatic transition grace period.
    pub grace_period_start_sec: Option<u64>,
    /// Dynamically rotated Root key (if updated via `RotateRootKey`).
    #[serde(default)]
    pub dynamic_root_key: Option<PublicKeyBytes>,
}

impl SignedGovernanceMessage {
    /// Serializes the governance message into a canonical byte vector for SHA-256 hashing and ML-DSA-65 signature verification.
    ///
    /// Each [`GovernanceAction`] variant is prefixed with a 1-byte opcode:
    ///
    /// | Opcode | Action Variant |
    /// |---|---|
    /// | `0x00` | `AppointMember` |
    /// | `0x02` | `LockCouncil` |
    /// | `0x04` | `RotateRootKey` |
    /// | `0x06` | `RotateCouncilMemberKey` |
    /// | `0x07` | `RemoveCouncilMember` |
    /// | `0x09` | `GrantPremiumName` |
    ///
    /// All variable-length fields are prefixed with `u32_be(len)` to prevent canonicalization ambiguity.
    /// The message closes with `u32_be(council_size_at_proposal)` and `u64_be(timestamp_sec)`.
    ///
    /// # Returns
    ///
    /// A deterministic `Vec<u8>` suitable for SHA-256 hashing to derive the action hash,
    /// or for ML-DSA-65 signature verification.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match &self.action {
            GovernanceAction::AppointMember { key } => {
                buf.push(0x00);
                buf.extend_from_slice(key.as_slice());
            }

            GovernanceAction::LockCouncil => {
                buf.push(0x02);
            }

            GovernanceAction::RotateRootKey { new_key } => {
                buf.push(0x04);
                buf.extend_from_slice(new_key.as_slice());
            }
            GovernanceAction::RotateCouncilMemberKey { target_key, new_key } => {
                buf.push(0x06);
                buf.extend_from_slice(target_key.as_slice());
                buf.extend_from_slice(new_key.as_slice());
            }
            GovernanceAction::RemoveCouncilMember { target_key } => {
                buf.push(0x07);
                buf.extend_from_slice(target_key.as_slice());
            }


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
        }

        buf.extend_from_slice(&self.council_size_at_proposal.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_sec.to_be_bytes());
        buf
    }
}
