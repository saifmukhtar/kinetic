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
    /// Calculates the base hardware iteration requirement.
    /// This is now a fixed value defined in network.json and updated via OTA network upgrades.
    pub fn calculate_hardware_anchor(&self) -> u64 {
        crate::constants::BENCHMARK_BASE_ITERATIONS
    }

    /// Calculate required iterations for a name based on length and hardware anchor
    pub fn required_iterations(
        &self,
        name: &str,
        drand_randomness: &[u8],
    ) -> u64 {
        let normalized_name = crate::types::names::normalize_name(name);
        let apex = crate::types::names::extract_apex_domain(&normalized_name);
        let label = apex
            .strip_suffix(crate::constants::TLD_SUFFIX)
            .unwrap_or(&apex);
        self.required_iterations_by_label(label, drand_randomness)
    }

    /// Calculate required iterations for a specific label
    pub fn required_iterations_by_label(
        &self,
        label: &str,
        drand_randomness: &[u8],
    ) -> u64 {
        if crate::config::is_dev_mode() {
            return crate::constants::DEV_MODE_ITERATIONS;
        }

        let len = label.len();
        let base = self.calculate_hardware_anchor();
        let tm = crate::constants::BENCHMARK_TARGET_MINUTES as u64;

        // "Squatter Cliff" curve dynamically adjusting to the hardware time target
        match len {
            0 | 1 => (base * 52_596_000) / tm, // 100 years (Reserved/Impossible)
            2 => (base * 43_200) / tm,         // 30 days
            3 => (base * 34_560) / tm,         // 24 days
            4 => (base * 21_600) / tm,         // 15 days
            5 => (base * 1_440) / tm,          // 1 day
            6 => (base * 720) / tm,            // 12 hours
            7 => (base * 150) / tm,            // 2.5 hours
            8..=10 => (base * 120) / tm,       // 2 hours
            11..=17 => (base * 90) / tm,       // 1.5 hours
            18..=20 => (base * 60) / tm,       // 1 hour
            21..=62 => base,                   // Baseline (always takes exactly `tm` minutes)
            63 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(label.as_bytes());
                hasher.update(drand_randomness);
                let result = hasher.finalize();

                // Unbiased extraction: combine first 4 bytes into u32, modulo 100
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&result[0..4]);
                let val = u32::from_be_bytes(bytes);
                let num = (val % 100) as u8;

                match num {
                    63 => (base * 63) / (tm * 60),                  // 63 Seconds (Jackpot!)
                    0..=10 => (base * 63) / tm,                     // 63 Minutes
                    11..=20 => (base * 63 * 60) / tm,               // 63 Hours
                    21..=30 => (base * 63 * 60 * 24) / tm,          // 63 Days
                    31..=40 => (base * 63 * 60 * 24 * 7) / tm,      // 63 Weeks
                    41..=50 => (base * 63 * 60 * 24 * 30) / tm,     // 63 Months
                    51..=62 | 64..=70 => (base * 63 * 60 * 24 * 365) / tm, // 63 Years
                    71..=80 => (base * 63 * 60 * 24 * 3650) / tm,   // 63 Decades
                    81..=90 => (base * 63 * 60 * 24 * 36500) / tm,  // 63 Centuries
                    _ => (base * 63 * 60 * 24 * 365000) / tm,       // 63 Millennia
                }
            }
            _ => base, // Fallback
        }
    }

    /// Calculate the cost to steal a name based on how long it has been offline
    pub fn steal_difficulty(&self, base_iterations: u64, rounds_idle: u64) -> u64 {
        let idle_plus = rounds_idle.saturating_add(1) as u128;
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
        let a = params.required_iterations("a", &[0u8; 32]);
        let ab = params.required_iterations("ab", &[0u8; 32]);
        let abc = params.required_iterations("abc", &[0u8; 32]);
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
