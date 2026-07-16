/// Parameters for the network's consensus mechanisms.
pub struct ConsensusParams {
    /// Number of rounds a name must be inactive before the steal difficulty decays.
    pub steal_target_rounds: u64,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            steal_target_rounds: crate::constants::STEAL_TARGET_ROUNDS,
        }
    }
}

impl ConsensusParams {
    /// Calculates the base hardware iteration requirement for a given round,
    /// doubling every `hardware_drift_rounds`.
    pub fn calculate_hardware_anchor(&self, _current_round: u64) -> u64 {
        crate::constants::BENCHMARK_BASE_ITERATIONS
    }

    /// Calculate required iterations for a name based on length and hardware anchor
    pub fn required_iterations(&self, name: &str, current_round: u64) -> u64 {
        let normalized_name = crate::types::normalize_name(name);

        let label = normalized_name
            .strip_suffix(crate::constants::TLD_SUFFIX)
            .unwrap_or(&normalized_name);
        self.required_iterations_by_label(label, current_round)
    }

    /// Calculate required iterations for a specific label
    pub fn required_iterations_by_label(&self, label: &str, current_round: u64) -> u64 {
        if crate::config::is_dev_mode() {
            return 1000;
        }

        let len = label.len();
        let base = self.calculate_hardware_anchor(current_round);

        // "Squatter Cliff" curve (1x = 30 minutes)
        match len {
            0 | 1 => base * 1_753_200, // 100 years (Reserved/Impossible)
            2 => base * 7_200,         // 5 months
            3 => base * 4_320,         // 3 months
            4 => base * 720,           // 15 days
            5 => base * 48,            // 1 day
            6 => base * 24,            // 12 hours
            7 => base * 5,             // 2.5 hours
            8..=10 => base * 4,        // 2 hours
            11..=17 => base * 3,       // 1.5 hours
            18..=20 => base * 2,       // 1 hour
            21..=62 => base,           // 30 minutes (Baseline)
            63 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(label.as_bytes());
                hasher.update(current_round.to_be_bytes());
                let result = hasher.finalize();
                let hex_string = hex::encode(result);

                let digits: String = hex_string.chars().filter(|c| c.is_ascii_digit()).collect();
                let first_two = if digits.len() >= 2 {
                    &digits[0..2]
                } else {
                    "99"
                };
                let num: u8 = first_two.parse().unwrap_or(99);

                match num {
                    63 => (base * 63) / 1800,              // 63 Seconds (Jackpot!)
                    0..=10 => (base * 63) / 30,            // 63 Minutes
                    11..=20 => base * 126,                 // 63 Hours
                    21..=30 => base * 3024,                // 63 Days
                    31..=40 => base * 21168,               // 63 Weeks
                    41..=50 => base * 92043,               // 63 Months
                    51..=62 | 64..=70 => base * 1_104_516, // 63 Years
                    71..=80 => base * 11_045_160,          // 63 Decades
                    81..=90 => base * 110_451_600,         // 63 Centuries
                    _ => base * 1_104_516_000,             // 63 Millennia
                }
            }
            _ => base, // Fallback
        }
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

    // Hardware drift is managed manually via network updates.

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
