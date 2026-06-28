pub struct ConsensusParams {
    pub decay_rate: f64,
    pub hibernation_multiplier: f64,
    pub steal_target_rounds: f64,
    pub hibernation_discount_factor: f64,
    pub hardware_drift_rounds: f64,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            decay_rate: 0.7,
            hibernation_multiplier: 45.0,
            steal_target_rounds: 21_024_000.0, // Exactly 2 years of 3s rounds (Quicknet)
            hibernation_discount_factor: 0.5,
            hardware_drift_rounds: 21_024_000.0, // 2 years at 3s/round (Quicknet)
        }
    }
}

impl ConsensusParams {
    /// The hardcoded public key allowed to claim Genesis names.
    pub const GENESIS_PUBKEY: Option<[u8; 32]> = Some([
        21, 62, 43, 16, 185, 42, 33, 65, 183, 232, 92, 246, 118,
        183, 35, 90, 83, 17, 115, 232, 249, 152, 11, 186, 114, 183, 185, 107, 11, 104, 227, 72
    ]);

    /// The exact list of names the Genesis Key is allowed to claim.
    pub const GENESIS_ALLOWLIST: [&'static str; 10] = [
        "saif", "saifmukhtar", "admin", "kinetic", "root",
        "genesis", "dev", "test", "system", "network"
    ];

    /// The Drand pulse when the network launches.
    pub const GENESIS_START_PULSE: u64 = 10_900_000; // Aligned with recent Quicknet rounds for launch

    /// The number of pulses (e.g. 7 days = 20,160 pulses at 30s) the Genesis Exclusivity window lasts.
    pub const GENESIS_EXPIRY_ROUNDS: u64 = 20_160;

    /// Calculate base iterations anchor adjusted for hardware advancements over time
    pub fn calculate_hardware_anchor(&self, current_round: u64) -> f64 {
        // Base starting point for 0 drift
        let genesis_base: f64 = 1_000_000.0;
        let drift = current_round as f64 / self.hardware_drift_rounds;
        // Doubles every hardware_drift_rounds
        genesis_base * 2.0f64.powf(drift)
    }

    /// Calculate required iterations for a name based on length and hardware anchor
    pub fn required_iterations(&self, name: &str, current_round: u64, pubkey: &[u8]) -> u64 {
        if crate::config::is_dev_mode() {
            return 1000;
        }

        let normalized_name = crate::types::normalize_name(name);
        
        // --- Genesis Rules ---
        if let Some(genesis_pk) = Self::GENESIS_PUBKEY {
            // Strip the `.kin` to compare against GENESIS_ALLOWLIST
            let label_without_tld = normalized_name.strip_suffix(".kin").unwrap_or(&normalized_name);
            if Self::GENESIS_ALLOWLIST.contains(&label_without_tld) {
                // If it's the genesis key and we are within the launch window, required iterations is 0!
                if pubkey == genesis_pk {
                    if current_round >= Self::GENESIS_START_PULSE && current_round < Self::GENESIS_START_PULSE + Self::GENESIS_EXPIRY_ROUNDS {
                        return 0;
                    }
                }
            }
        }
        // ---------------------

        let label = normalized_name.strip_suffix(".kin").unwrap_or(&normalized_name);
        let len = label.len() as f64;
        
        let base = self.calculate_hardware_anchor(current_round);
        
        // Multiplier decays exponentially as length increases
        let multiplier = 1.0 + 40000.0 * (-self.decay_rate * len).exp();
        
        (base * multiplier) as u64
    }

    /// Calculate how many drand rounds of exemption a given VDF proof yields
    pub fn hibernation_exemption_rounds(&self, iterations: u64) -> u64 {
        ((iterations as f64).sqrt() * self.hibernation_multiplier) as u64
    }

    /// Calculate the cost to steal a name based on how long it has been offline
    pub fn steal_difficulty(&self, base_iterations: u64, rounds_idle: u64) -> u64 {
        let base_f64 = base_iterations as f64;
        let idle_f64 = rounds_idle as f64;
        
        let ratio = self.steal_target_rounds / (idle_f64 + 1.0);
        let multiplier = f64::max(1.0, ratio * ratio);
        
        (base_f64 * multiplier) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_override() {
        let params = ConsensusParams::default();
        let pk = ConsensusParams::GENESIS_PUBKEY.unwrap();
        // Inside launch window
        let iters = params.required_iterations("saif.kin", ConsensusParams::GENESIS_START_PULSE, &pk);
        assert_eq!(iters, 0);

        // Outside launch window
        let outside = ConsensusParams::GENESIS_START_PULSE + ConsensusParams::GENESIS_EXPIRY_ROUNDS + 1;
        let iters_out = params.required_iterations("saif.kin", outside, &pk);
        assert!(iters_out > 0);

        // Wrong key
        let wrong_pk = [0u8; 32];
        let iters_wrong = params.required_iterations("saif.kin", ConsensusParams::GENESIS_START_PULSE, &wrong_pk);
        assert!(iters_wrong > 0);
    }

    #[test]
    fn test_decay_length() {
        let params = ConsensusParams::default();
        let pk = [0u8; 32];
        let a = params.required_iterations("a", 0, &pk);
        let ab = params.required_iterations("ab", 0, &pk);
        let abc = params.required_iterations("abc", 0, &pk);
        assert!(a > ab);
        assert!(ab > abc);
    }

    #[test]
    fn test_hardware_drift() {
        let params = ConsensusParams::default();
        let pk = [0u8; 32];
        let base = params.required_iterations("abcd", 0, &pk);
        let drift_round = params.hardware_drift_rounds as u64;
        let drifted = params.required_iterations("abcd", drift_round, &pk);
        
        // At exact hardware_drift_rounds, required iterations should be 2x the base
        assert_eq!(drifted, base * 2);
    }

    #[test]
    fn test_steal_difficulty() {
        let params = ConsensusParams::default();
        let target = params.steal_target_rounds as u64;
        
        let diff_early = params.steal_difficulty(100, target / 2);
        assert!(diff_early > 100); // 4x multiplier
        
        let diff_late = params.steal_difficulty(100, target * 2);
        assert_eq!(diff_late, 100); // 1x multiplier (min)
    }

    #[test]
    fn test_hibernation_exemption() {
        let params = ConsensusParams::default();
        let exempt = params.hibernation_exemption_rounds(10_000);
        // sqrt(10000) = 100. 100 * 45 = 4500
        assert_eq!(exempt, 4500);
    }
}
