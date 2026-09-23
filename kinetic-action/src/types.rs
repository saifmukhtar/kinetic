//! Data structures and serialized action types for network action.
//! Network action payloads and state models.
//!
//! Defines the complete set of [`NetworkAction`] variants, the persistent [`ActionState`],
//! the [`SignedActionMessage`] proposal envelope, and canonical byte serialization.
//!
//! ## Protocol Context
//!
//! All action state changes follow a direct execution protocol:
//! 1. A [`SignedActionMessage`] is broadcast with a single cryptographic signature.
//! 2. Verification by the active [`ActionEngine`](crate::traits::ActionEngine)
//!    determines whether the action is immediately executed or rejected.
//!
//! In **Sovereign mode**, the Sovereign key acts as a single-signer authority.
use std::collections::HashMap;

pub use kinetic_types::action::{
    Hash256, NetworkAction, SovereignSignature, SignedNetworkAction,
};

/// Verifies a Sovereign signature over a message byte slice.
///
/// # Security
///
/// Returns `true` if the signature is cryptographically valid for `pubkey`; `false` if key decoding,
/// signature parsing, or verification fails.
/// 
/// # Examples
/// ```rust,no_run
/// use kinetic_action::types::verify_signature;
/// use kinetic_primitives::kinetic_keypair::SovereignPubKey;
/// 
/// let pubkey = SovereignPubKey(vec![0; kinetic_primitives::KINETIC_PUBKEY_LENGTH]);
/// let msg = b"hello";
/// let sig = vec![0; 64];
/// // Returns true only if the Sovereign signature strictly matches the pubkey and msg.
/// let is_valid = verify_sovereign_signature(&pubkey, msg, &sig);
/// ```
pub fn verify_sovereign_signature(pubkey: &kinetic_primitives::keypairs::SovereignPubKey, msg: &[u8], sig: &[u8]) -> bool {
    pubkey.verify(msg, sig).is_ok()
}

/// Side effects produced when a network action is executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionEffect {


    /// The Sovereign key was successfully rotated.
    SovereignKeyRotated {
        /// The new Sovereign public key.
        new_key: kinetic_primitives::keypairs::SovereignPubKey,
    },
    /// The network has been emergency halted by the Sovereign key.
    NetworkHalted,
    /// The network has been resumed by the Sovereign key.
    NetworkResumed,
}

/// Persistent on-disk state container for the network action subsystem.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionState {
    /// Genesis Kyn when action tracking started.
    pub genesis_kyn: kinetic_kyn::types::GenesisKyn,
    /// Active Sovereign public key controlling the network.
    #[serde(with = "kinetic_types::pubkey_serde::opt_sovereign_serde")]
    pub active_sovereign_key: Option<kinetic_primitives::keypairs::SovereignPubKey>,
    /// Master boolean flag if the network is currently paused.
    #[serde(default)]
    pub is_halted: bool,
    /// The exact Kyn when the network was halted (if currently halted).
    #[serde(default)]
    pub halt_start_kyn: Option<kinetic_kyn::types::HaltStartKyn>,
    /// Total number of KineticTime kyns the network has been paused for since genesis.
    #[serde(default)]
    pub total_paused_kyns: u64,
    /// Historical timeline of all network pauses (start_kyn, end_kyn).
    #[serde(default)]
    pub pause_history: Vec<(kinetic_kyn::types::StartKyn, kinetic_kyn::types::EndKyn)>,
    #[serde(default)]
    /// Actions that have already been executed (and their execution timestamps).
    pub executed_hashes: HashMap<Hash256, kinetic_kyn::types::Kyn>,
    #[serde(default)]
    /// Append-only log of all executed signed action messages (used for P2P state syncing).
    pub action_log: Vec<kinetic_types::action::SignedNetworkAction>,

}

impl ActionState {
    /// Calculates the exact number of paused kyns that occurred *after* a specific target kyn.
    ///
    /// # Examples
    /// ```rust
    /// use kinetic_action::types::ActionState;
    /// use kinetic_kyn::types::Kyn;
    /// use std::collections::HashMap;
    /// 
    /// let mut state = ActionState {
    ///     genesis_kyn: Kyn(0),
    ///     active_sovereign_key: None,
    ///     is_halted: false,
    ///     halt_start_kyn: None,
    ///     total_paused_kyns: 0,
    ///     pause_history: vec![(Kyn(100), Kyn(200))], // Paused for 100 kyns
    ///     executed_hashes: HashMap::new(),
    ///     action_log: vec![],

    /// };
    /// 
    /// // If an event happened at kyn 50, it experienced all 100 paused kyns.
    /// assert_eq!(state.paused_kyns_since(Kyn(50)), 100);
    /// 
    /// // If an event happened at kyn 150, it only experienced the last 50 paused kyns.
    /// assert_eq!(state.paused_kyns_since(Kyn(150)), 50);
    /// ```
    pub fn paused_kyns_since(&self, target_kyn: kinetic_kyn::types::Kyn) -> u64 {
        let mut total = 0;
        for &(start, end) in &self.pause_history {
            if end.as_u64() <= target_kyn.0 {
                // Pause happened entirely before the target kyn, ignore.
                continue;
            }
            if start.as_u64() >= target_kyn.0 {
                // Pause happened entirely after the target kyn, add full duration.
                total += end.as_u64().saturating_sub(start.as_u64());
            } else {
                // Pause started before target kyn, but ended after. Only add the overlapping part.
                total += end.as_u64().saturating_sub(target_kyn.0);
            }
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kinetic_kyn::types::Kyn;
    use std::collections::HashMap;

    fn mock_state() -> ActionState {
        ActionState {
            genesis_kyn: kinetic_kyn::types::GenesisKyn::from(0),
            active_sovereign_key: None,
            is_halted: false,
            halt_start_kyn: None,
            total_paused_kyns: 0,
            pause_history: Vec::new(),
            executed_hashes: HashMap::new(),
            action_log: Vec::new(),

        }
    }

    #[test]
    fn test_pause_history_double_mapping_flaw() {
        let mut state = mock_state();
        // Pause happens between kyns 1000 and 1100 (100 kyns)
        state.pause_history.push((kinetic_kyn::types::StartKyn::from(1000), kinetic_kyn::types::EndKyn::from(1100)));

        // Name is registered AFTER the pause, at kyn 2000
        let target_kyn = 2000;

        // It should get 0 paused kyns back (fixing the double-mapping flaw)
        assert_eq!(state.paused_kyns_since(Kyn(target_kyn)), 0);
    }

    #[test]
    fn test_pause_history_renewal_in_the_middle() {
        let mut state = mock_state();
        // Pause 1: kyns 1000 to 1100 (100 kyns)
        state.pause_history.push((kinetic_kyn::types::StartKyn::from(1000), kinetic_kyn::types::EndKyn::from(1100)));
        // Pause 2: kyns 3000 to 3100 (100 kyns)
        state.pause_history.push((kinetic_kyn::types::StartKyn::from(3000), kinetic_kyn::types::EndKyn::from(3100)));

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
        state.pause_history.push((kinetic_kyn::types::StartKyn::from(1000), kinetic_kyn::types::EndKyn::from(1100)));
        // Pause 2: kyns 3000 to 3100 (100 kyns)
        state.pause_history.push((kinetic_kyn::types::StartKyn::from(3000), kinetic_kyn::types::EndKyn::from(3100)));

        // Name was registered before BOTH pauses, at kyn 500
        let target_pulse = 500;

        // They should get BOTH pauses credited (200 kyns)
        assert_eq!(state.paused_kyns_since(Kyn(target_pulse)), 200);
    }

    #[test]
    fn test_pause_history_overlapping_pause() {
        let mut state = mock_state();
        // Pause: kyns 1000 to 1100 (100 kyns)
        state.pause_history.push((kinetic_kyn::types::StartKyn::from(1000), kinetic_kyn::types::EndKyn::from(1100)));

        // Name was registered *during* the pause, at kyn 1050
        let target_pulse = 1050;

        // They should only get the portion of the pause that happened AFTER they registered (50 kyns)
        assert_eq!(state.paused_kyns_since(Kyn(target_pulse)), 50);
    }
}

/// Configuration constants required for action evaluation.
#[derive(Debug, Clone)]
pub struct ActionConfig {
    /// The Sovereign public key hex string used to verify actions.
    pub sovereign_key_hex: String,
    /// The maximum age (in kyns) a network action is allowed to be before it is rejected as stale.
    pub max_age_kyns: u64,
    /// Whether the network is running in dev mode (bypasses Sovereign key validation).
    pub is_dev_mode: bool,
    /// The action model to use ("sovereign" or "permissionless").
    pub action_model: String,
}
