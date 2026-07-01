pub struct ConsensusParams {
    pub steal_target_rounds: u64,
    pub hardware_drift_rounds: u64,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            steal_target_rounds: 21_024_000, // Exactly 2 years of 3s rounds (Quicknet)
            hardware_drift_rounds: 21_024_000, // 2 years at 3s/round (Quicknet)
        }
    }
}

impl ConsensusParams {
    /// The hardcoded public key allowed to claim Genesis names.
    pub const GENESIS_PUBKEY: Option<[u8; 32]> = Some([
        148, 100, 103, 139, 110, 187, 7, 207, 47, 201, 200, 160, 12, 86, 194, 76, 25, 176, 157,
        180, 249, 145, 27, 251, 254, 117, 11, 19, 53, 249, 131, 236,
    ]);

    /// The exact list of names the Genesis Key is allowed to claim.
    pub const GENESIS_ALLOWLIST: [&'static str; 17] = [
        "saif",
        "saifmukhtar",
        "admin",
        "kinetic",
        "root",
        "genesis",
        "test",
        "system",
        "network",
        "example",
        "kin",
        "web",
        "docs",
        "blog",
        "s",
        "security",
        "mail",
    ];

    /// The Drand pulse when the network launches.
    pub const GENESIS_START_PULSE: u64 = 10_900_000; // Aligned with recent Quicknet rounds for launch
                                                     // Note: No expiry window — the genesis key permanently gets 0-cost registration
                                                     // for the hardcoded GENESIS_ALLOWLIST only. Since the allowlist is fixed at compile
                                                     // time, no additional names can ever be claimed via this path regardless of key.

    // Double Exponential Cliff: M(L) = 500000 * exp(-2.0 * L) + 250 * exp(-0.5 * L) + 5
    const MULTIPLIERS: [u64; 20] = [
        67824, 67824, 9255, 1300, 207, 48, 21, 13, 10, 8, 7, 6, 6, 5, 5, 5, 5, 5, 5, 5,
    ];

    pub fn calculate_hardware_anchor(&self, current_round: u64) -> u64 {
        // Base starting point for 0 drift (22-bit iterations)
        let genesis_base: u64 = 4_194_304;

        let mut drift_rounds = current_round;
        let max_rounds = 5 * self.hardware_drift_rounds; // Max 32x multiplier (2^5)
        if drift_rounds > max_rounds {
            drift_rounds = max_rounds;
        }

        let full_doublings = drift_rounds / self.hardware_drift_rounds;
        let remainder = drift_rounds % self.hardware_drift_rounds;

        let base = genesis_base << full_doublings;
        // Deterministic integer linear interpolation for partial hardware drift
        let extra = (base * remainder) / self.hardware_drift_rounds;
        base + extra
    }

    /// Calculate required iterations for a name based on length and hardware anchor
    pub fn required_iterations(&self, name: &str, current_round: u64, pubkey: &[u8]) -> u64 {
        let normalized_name = crate::types::normalize_name(name);

        // --- Genesis Rules ---
        if let Some(genesis_pk) = Self::GENESIS_PUBKEY {
            // Strip the `.kin` to compare against GENESIS_ALLOWLIST
            let label_without_tld = normalized_name
                .strip_suffix(".kin")
                .unwrap_or(&normalized_name);
            if Self::GENESIS_ALLOWLIST.contains(&label_without_tld) {
                // If it's the genesis key, required iterations is 0!
                if pubkey == genesis_pk {
                    return 0;
                }
            }
        }
        // ---------------------

        let label = normalized_name
            .strip_suffix(".kin")
            .unwrap_or(&normalized_name);
        self.required_iterations_by_length(label.len(), current_round)
    }

    /// Calculate required iterations given just the length (used by blind VDF prover)
    pub fn required_iterations_by_length(&self, len: usize, current_round: u64) -> u64 {
        if crate::config::is_dev_mode() {
            return 1000;
        }

        let base = self.calculate_hardware_anchor(current_round);

        // Multiplier based on the Double Exponential Cliff
        let multiplier = if len < 20 {
            Self::MULTIPLIERS[len]
        } else {
            // Flat tail: anything 20 or longer gets the lowest multiplier (pinned at 5)
            5
        };

        base * multiplier
    }

    /// Calculate how many drand rounds of exemption a given VDF proof yields
    pub fn hibernation_exemption_rounds(&self, iterations: u64) -> u64 {
        ((iterations as f64).sqrt() * 45.0) as u64
    }

    /// Calculate the cost to steal a name based on how long it has been offline
    pub fn steal_difficulty(&self, base_iterations: u64, rounds_idle: u64) -> u64 {
        let idle_plus = rounds_idle + 1;
        let multiplier = if self.steal_target_rounds > idle_plus {
            let target_sq = self.steal_target_rounds * self.steal_target_rounds;
            let idle_sq = idle_plus * idle_plus;
            target_sq / idle_sq
        } else {
            1
        };

        base_iterations * std::cmp::max(1, multiplier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_override() {
        let params = ConsensusParams::default();
        let pk = ConsensusParams::GENESIS_PUBKEY.unwrap();

        // Genesis key always gets 0 iterations for allowlisted names — no time window.
        let iters_at_launch =
            params.required_iterations("saif.kin", ConsensusParams::GENESIS_START_PULSE, &pk);
        assert_eq!(iters_at_launch, 0);

        // Still 0 long after launch — permanent grant for the fixed allowlist.
        let iters_later = params.required_iterations(
            "saif.kin",
            ConsensusParams::GENESIS_START_PULSE + 1_000_000,
            &pk,
        );
        assert_eq!(iters_later, 0);

        // Wrong key — must compute full VDF even for allowlisted names.
        let wrong_pk = [0u8; 32];
        let iters_wrong =
            params.required_iterations("saif.kin", ConsensusParams::GENESIS_START_PULSE, &wrong_pk);
        assert!(iters_wrong > 0);

        // Name not in allowlist — genesis key gets no special treatment.
        let iters_unlisted =
            params.required_iterations("random.kin", ConsensusParams::GENESIS_START_PULSE, &pk);
        assert!(iters_unlisted > 0);
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
        let drift_round = params.hardware_drift_rounds;
        let drifted = params.required_iterations("abcd", drift_round, &pk);

        // At exact hardware_drift_rounds, required iterations should be 2x the base
        assert_eq!(drifted, base * 2);
    }

    #[test]
    fn test_steal_difficulty() {
        let params = ConsensusParams::default();
        let target = params.steal_target_rounds;

        let diff_early = params.steal_difficulty(100, target / 2);
        assert!(diff_early > 100); // 4x multiplier

        let diff_late = params.steal_difficulty(100, target * 2);
        assert_eq!(diff_late, 100); // 1x multiplier (min)
    }
}
