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

pub use kinetic_types::governance::{
    GovernanceAction, Hash256, PublicKeyBytes, SignatureBytes, SignedGovernanceMessage,
};

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
    /// Historical timeline of all network pauses (start_round, end_round).
    #[serde(default)]
    pub pause_history: Vec<(u64, u64)>,
    #[serde(default)]
    /// Actions that have already been executed (and their execution timestamps).
    pub executed_hashes: HashMap<Hash256, u64>,
}

impl GovernanceState {
    /// Calculates the exact number of paused rounds that occurred *after* a specific target pulse.
    pub fn paused_rounds_since(&self, target_pulse: u64) -> u64 {
        let mut total = 0;
        for &(start, end) in &self.pause_history {
            if end <= target_pulse {
                // Pause happened entirely before the target pulse, ignore.
                continue;
            }
            if start >= target_pulse {
                // Pause happened entirely after the target pulse, add full duration.
                total += end.saturating_sub(start);
            } else {
                // Pause overlapped the target pulse, add only the portion after.
                total += end.saturating_sub(target_pulse);
            }
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn mock_state() -> GovernanceState {
        GovernanceState {
            genesis_timestamp_sec: 0,
            active_root_key: None,
            is_halted: false,
            total_paused_rounds: 0,
            pause_history: vec![],
            executed_hashes: HashMap::new(),
        }
    }

    #[test]
    fn test_pause_history_double_granting_flaw() {
        let mut state = mock_state();
        // Pause happens between rounds 1000 and 1100 (100 rounds)
        state.pause_history.push((1000, 1100));

        // Domain is registered AFTER the pause, at round 2000
        let target_pulse = 2000;
        
        // It should get 0 paused rounds back (fixing the double-granting flaw)
        assert_eq!(state.paused_rounds_since(target_pulse), 0);
    }

    #[test]
    fn test_pause_history_renewal_in_the_middle() {
        let mut state = mock_state();
        // Pause 1: rounds 1000 to 1100 (100 rounds)
        state.pause_history.push((1000, 1100));
        // Pause 2: rounds 3000 to 3100 (100 rounds)
        state.pause_history.push((3000, 3100));

        // User renewed the domain at round 2000
        // (After pause 1, but before pause 2)
        let target_pulse = 2000;

        // They should only get Pause 2 (100 rounds) credited
        assert_eq!(state.paused_rounds_since(target_pulse), 100);
    }

    #[test]
    fn test_pause_history_back_to_back_pauses() {
        let mut state = mock_state();
        // Pause 1: rounds 1000 to 1100 (100 rounds)
        state.pause_history.push((1000, 1100));
        // Pause 2: rounds 3000 to 3100 (100 rounds)
        state.pause_history.push((3000, 3100));

        // Domain was registered before BOTH pauses, at round 500
        let target_pulse = 500;

        // They should get BOTH pauses credited (200 rounds)
        assert_eq!(state.paused_rounds_since(target_pulse), 200);
    }

    #[test]
    fn test_pause_history_overlapping_pause() {
        let mut state = mock_state();
        // Pause: rounds 1000 to 1100 (100 rounds)
        state.pause_history.push((1000, 1100));

        // Domain was registered *during* the pause, at round 1050
        let target_pulse = 1050;

        // They should only get the portion of the pause that happened AFTER they registered (50 rounds)
        assert_eq!(state.paused_rounds_since(target_pulse), 50);
    }
}
