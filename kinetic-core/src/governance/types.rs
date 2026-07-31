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
//! In **Sovereign mode**, the Root key acts as a single-signer authority.

use ml_dsa::signature::Verifier;
use ml_dsa::KeyInit;
use ml_dsa::MlDsa65;
use std::collections::HashMap;

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

/// Enumerates privileged protocol actions governed by network governance.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    /// Inform node subsystems of a premium domain revocation.
    PremiumNameRevoked {
        /// Revoked 1-character name.
        name: String,
    },
    /// The Sovereign Root key was successfully rotated.
    RootKeyRotated {
        /// The new Root public key.
        new_key: PublicKeyBytes,
    },
    /// The network has been emergency halted by the Root key.
    NetworkHalted,
    /// The network has been resumed by the Root key.
    NetworkResumed,
}

/// Proposal message container with signatures from authorized council members.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedGovernanceMessage {
    /// Target governance action payload.
    pub action: GovernanceAction,
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
    /// If Some, this key overrides the hardcoded genesis ROOT_PUBLIC_KEY_HEX.
    pub active_root_key: Option<PublicKeyBytes>,
    /// Whether the network registration engine is currently paused.
    #[serde(default)]
    pub is_halted: bool,
    /// Total number of drand rounds the network has been paused for since genesis.
    #[serde(default)]
    pub total_paused_rounds: u64,
    #[serde(default)]
    /// Actions that have already been executed (and their execution timestamps).
    pub executed_hashes: HashMap<Hash256, u64>,
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
