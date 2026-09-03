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
    kinetic_primitives::verify_mldsa(pubkey, msg, sig).is_ok()
}

/// Side effects produced when a governance action is executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceEffect {
    /// Inform node subsystems of a prime name mapping.
    PrimeMapped {
        /// Granted 1-character name.
        name: String,
        /// Recipient public key.
        target_pubkey: PublicKeyBytes,
    },
    /// Inform node subsystems of a prime name unmapping.
    PrimeUnmapped {
        /// Revoked 1-character name.
        name: String,
    },
    /// Inform node subsystems of an infrastructure name grant.
    InfraMapped {
        /// Granted Category 2 name.
        name: String,
        /// Recipient public key.
        target_pubkey: PublicKeyBytes,
    },
    /// Inform node subsystems of an infrastructure name revocation.
    InfraUnmapped {
        /// Revoked Category 2 name.
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
    /// Genesis Kyn when governance tracking started.
    pub genesis_kyn: kinetic_types::clock::Kyn,
    /// Active ML-DSA-65 root public key controlling the network.
    pub active_root_key: Option<PublicKeyBytes>,
    /// Master boolean flag if the network is currently paused.
    #[serde(default)]
    pub is_halted: bool,
    /// The exact Kyn when the network was halted (if currently halted).
    #[serde(default)]
    pub halt_start_kyn: Option<kinetic_types::clock::Kyn>,
    /// Total number of drand kyns the network has been paused for since genesis.
    #[serde(default)]
    pub total_paused_kyns: u64,
    /// Historical timeline of all network pauses (start_kyn, end_kyn).
    #[serde(default)]
    pub pause_history: Vec<(kinetic_types::clock::Kyn, kinetic_types::clock::Kyn)>,
    #[serde(default)]
    /// Actions that have already been executed (and their execution timestamps).
    pub executed_hashes: HashMap<Hash256, kinetic_types::clock::Kyn>,
    /// Active 1-character prime names and their associated ML-DSA-65 public keys.
    #[serde(default)]
    pub mapped_prime_names: HashMap<String, PublicKeyBytes>,
    /// Active infrastructure names and their associated ML-DSA-65 public keys.
    #[serde(default)]
    pub mapped_infra_names: HashMap<String, PublicKeyBytes>,
}

impl GovernanceState {
    /// Calculates the exact number of paused kyns that occurred *after* a specific target kyn.
    pub fn paused_kyns_since(&self, target_kyn: kinetic_types::clock::Kyn) -> u64 {
        let mut total = 0;
        for &(start, end) in &self.pause_history {
            if end <= target_kyn {
                // Pause happened entirely before the target kyn, ignore.
                continue;
            }
            if start >= target_kyn {
                // Pause happened entirely after the target kyn, add full duration.
                total += end.0.saturating_sub(start.0);
            } else {
                // Pause started before target kyn, but ended after. Only add the overlapping part.
                total += end.0.saturating_sub(target_kyn.0);
            }
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kinetic_types::clock::Kyn;
    use std::collections::HashMap;

    fn mock_state() -> GovernanceState {
        GovernanceState {
            genesis_kyn: Kyn(0),
            active_root_key: None,
            is_halted: false,
            halt_start_kyn: None,
            total_paused_kyns: 0,
            pause_history: Vec::new(),
            executed_hashes: HashMap::new(),
            mapped_prime_names: HashMap::new(),
            mapped_infra_names: HashMap::new(),
        }
    }

    #[test]
    fn test_pause_history_double_mapping_flaw() {
        let mut state = mock_state();
        // Pause happens between kyns 1000 and 1100 (100 kyns)
        state.pause_history.push((Kyn(1000), Kyn(1100)));

        // Name is registered AFTER the pause, at kyn 2000
        let target_kyn = 2000;

        // It should get 0 paused kyns back (fixing the double-mapping flaw)
        assert_eq!(state.paused_kyns_since(Kyn(target_kyn)), 0);
    }

    #[test]
    fn test_pause_history_renewal_in_the_middle() {
        let mut state = mock_state();
        // Pause 1: kyns 1000 to 1100 (100 kyns)
        state.pause_history.push((Kyn(1000), Kyn(1100)));
        // Pause 2: kyns 3000 to 3100 (100 kyns)
        state.pause_history.push((Kyn(3000), Kyn(3100)));

        // User renewed the name at kyn 2000
        // (After pause 1, but before pause 2)
        let target_pulse = 2000;

        // They should only get Pause 2 (100 kyns) credited
        assert_eq!(state.paused_kyns_since(Kyn(target_pulse)), 100);
    }

    #[test]
    fn test_pause_history_back_to_back_pauses() {
        let mut state = mock_state();
        // Pause 1: kyns 1000 to 1100 (100 kyns)
        state.pause_history.push((Kyn(1000), Kyn(1100)));
        // Pause 2: kyns 3000 to 3100 (100 kyns)
        state.pause_history.push((Kyn(3000), Kyn(3100)));

        // Name was registered before BOTH pauses, at kyn 500
        let target_pulse = 500;

        // They should get BOTH pauses credited (200 kyns)
        assert_eq!(state.paused_kyns_since(Kyn(target_pulse)), 200);
    }

    #[test]
    fn test_pause_history_overlapping_pause() {
        let mut state = mock_state();
        // Pause: kyns 1000 to 1100 (100 kyns)
        state.pause_history.push((Kyn(1000), Kyn(1100)));

        // Name was registered *during* the pause, at kyn 1050
        let target_pulse = 1050;

        // They should only get the portion of the pause that happened AFTER they registered (50 kyns)
        assert_eq!(state.paused_kyns_since(Kyn(target_pulse)), 50);
    }
}
