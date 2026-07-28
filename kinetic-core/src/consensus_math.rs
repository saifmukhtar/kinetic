//! Consensus difficulty math, Squatter Cliff curve, and inverse-square domain takeover calculations.
//!
//! # VDF Squatter Cliff Curve
//!
//! To prevent high-value short domain names from being trivially squatted, Kinetic requires
//! exponential VDF iteration effort for shorter domain labels:
//! - **1-char labels**: 100 years of sequential computation (permanently locked).
//! - **2-char labels**: 30 days of computation.
//! - **3 to 4-char labels**: 24 days down to 15 days.
//! - **5 to 20-char labels**: 1 day down to 1 hour.
//! - **21 to 62-char labels**: Baseline target time.
//!
//! # Inverse-Square Steal Decay Math
//!
//! When a domain owner fails to publish regular heartbeats, the iteration effort required
//! for a third party to claim ("steal") the domain decays via an inverse-square formula:
//!
//! $$\text{Multiplier} = \left(\frac{\text{steal\_target\_rounds}}{\text{rounds\_idle} + 1}\right)^2$$

/// Consensus parameters governing VDF difficulty and domain takeover decay rates.
pub struct ConsensusParams {
    /// Number of Drand rounds a domain must remain idle before takeover difficulty decays to $1\times$.
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
    /// Returns the baseline hardware anchor iteration benchmark defined for the network.
    pub fn calculate_hardware_anchor(&self) -> u64 {
        crate::constants::BENCHMARK_BASE_ITERATIONS
    }

    /// Calculates the required VDF iterations for a full `.kin` domain name.
    ///
    /// Normalizes the name, extracts the apex label, and evaluates difficulty against the Squatter Cliff curve.
    ///
    /// # Examples
    ///
    /// ```
    /// use kinetic_core::consensus_math::ConsensusParams;
    ///
    /// let params = ConsensusParams::default();
    /// let iterations = params.required_iterations("saif.kin", &[0u8; 32]);
    /// assert!(iterations > 0);
    /// ```
    pub fn required_iterations(&self, name: &str, drand_randomness: &[u8]) -> u64 {
        let normalized_name = crate::types::names::normalize_name(name);
        let apex = crate::types::names::extract_apex_domain(&normalized_name);
        let label = apex
            .strip_suffix(crate::constants::TLD_SUFFIX)
            .unwrap_or(&apex);
        self.required_iterations_by_label(label, drand_randomness)
    }

    /// Calculates required VDF iterations for a raw domain label based on the Squatter Cliff curve.
    ///
    /// In dev mode (`is_dev_mode()`), returns a fixed low iteration count ([`DEV_MODE_ITERATIONS`](crate::constants::DEV_MODE_ITERATIONS)).
    pub fn required_iterations_by_label(&self, label: &str, _drand_randomness: &[u8]) -> u64 {
        if crate::config::is_dev_mode() {
            return crate::constants::DEV_MODE_ITERATIONS;
        }

        let len = label.len();
        let base = self.calculate_hardware_anchor();
        let tm = crate::constants::BENCHMARK_TARGET_MINUTES as u64;

        let calc = |multiplier: u64| -> u64 {
            ((base as u128 * multiplier as u128) / tm as u128) as u64
        };

        // "Squatter Cliff" curve dynamically adjusting to the hardware time target
        match len {
            0 | 1 => calc(crate::constants::CONSENSUS_SQUATTER_LEN_0_TO_1), // 100 years (Reserved/Impossible)
            2 => calc(crate::constants::CONSENSUS_SQUATTER_LEN_2),          // 30 days
            3 => calc(crate::constants::CONSENSUS_SQUATTER_LEN_3),          // 24 days
            4 => calc(crate::constants::CONSENSUS_SQUATTER_LEN_4),          // 15 days
            5 => calc(crate::constants::CONSENSUS_SQUATTER_LEN_5),          // 1 day
            6 => calc(crate::constants::CONSENSUS_SQUATTER_LEN_6),          // 12 hours
            7 => calc(crate::constants::CONSENSUS_SQUATTER_LEN_7),          // 2.5 hours
            8..=10 => calc(crate::constants::CONSENSUS_SQUATTER_LEN_8_TO_10), // 2 hours
            11..=17 => calc(crate::constants::CONSENSUS_SQUATTER_LEN_11_TO_17), // 1.5 hours
            18..=20 => calc(crate::constants::CONSENSUS_SQUATTER_LEN_18_TO_20), // 1 hour
            21..=63 => base, // Baseline (always takes exactly `tm` minutes)
            _ => base, // Fallback
        }
    }

    /// Calculates the VDF iteration effort required to claim an idle domain.
    ///
    /// Applies an inverse-square multiplier based on `rounds_idle`. As `rounds_idle` increases,
    /// the required effort decays down to the baseline `base_iterations`.
    ///
    /// # Examples
    ///
    /// ```
    /// use kinetic_core::consensus_math::ConsensusParams;
    ///
    /// let params = ConsensusParams::default();
    /// let base = 100;
    /// // Early takeover attempt requires high multiplier
    /// let diff_early = params.steal_difficulty(base, 100);
    /// assert!(diff_early >= base);
    /// ```
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
