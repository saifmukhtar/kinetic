/// Parameters for the network's consensus mechanisms.
pub struct ConsensusParams {
    /// Number of rounds a name must be inactive before the steal difficulty decays.
    pub steal_target_rounds: u64,
    /// Number of rounds it takes for hardware speed to theoretically double.
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
    // Double Exponential Cliff: M(L) = 500000 * exp(-2.0 * L) + 250 * exp(-0.5 * L) + 5
    const MULTIPLIERS: [u64; 20] = [
        67824, 67824, 9255, 1300, 207, 48, 21, 13, 10, 8, 7, 6, 6, 5, 5, 5, 5, 5, 5, 5,
    ];

    /// TODO(BENCHMARK): These values need to be updated with correct chiavdf benchmarks.
    pub const TODO_BENCHMARK_BASE_ITERATIONS: u64 = 4_194_304;

    /// Calculates the base hardware iteration requirement for a given round,
    /// doubling every `hardware_drift_rounds`.
    pub fn calculate_hardware_anchor(&self, current_round: u64) -> u64 {
        // Base starting point for 0 drift (22-bit iterations)
        let genesis_base: u64 = Self::TODO_BENCHMARK_BASE_ITERATIONS;

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
    pub fn required_iterations(&self, name: &str, current_round: u64) -> u64 {
        let normalized_name = crate::types::normalize_name(name);

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



    /// Calculate the cost to steal a name based on how long it has been offline
    pub fn steal_difficulty(&self, base_iterations: u64, rounds_idle: u64) -> u64 {
        let idle_plus = (rounds_idle + 1) as u128;
        let target_rounds = self.steal_target_rounds as u128;
        
        let multiplier = if target_rounds > idle_plus {
            let target_sq = target_rounds * target_rounds;
            let idle_sq = idle_plus * idle_plus;
            target_sq / idle_sq
        } else {
            1
        };

        let difficulty = (base_iterations as u128) * std::cmp::max(1, multiplier);
        
        // Cap at u64::MAX to prevent wrapping to a low difficulty
        if difficulty > (u64::MAX as u128) {
            u64::MAX
        } else {
            difficulty as u64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_decay_length() {
        let params = ConsensusParams::default();
        let _pk = [0u8; 32];
        let a = params.required_iterations("a", 0);
        let ab = params.required_iterations("ab", 0);
        let abc = params.required_iterations("abc", 0);
        assert!(a > ab);
        assert!(ab > abc);
    }

    #[test]
    fn test_hardware_drift() {
        let params = ConsensusParams::default();
        let _pk = [0u8; 32];
        let base = params.required_iterations("abcd", 0);
        let drift_round = params.hardware_drift_rounds;
        let drifted = params.required_iterations("abcd", drift_round);

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
