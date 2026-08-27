//! Consensus difficulty math, Name Difficulty Curve (NDC), and inverse-square name takeover calculations.
//!
//! # Name Difficulty Curve (NDC)
//!
//! To prevent high-value short names from being trivially registered, Kinetic requires
//! exponential VDF iteration effort for shorter name labels:
//! - **1-char labels**: 100 years of sequential computation (permanently locked).
//! - **2-char labels**: 30 days of computation.
//! - **3 to 4-char labels**: 24 days down to 15 days.
//! - **5 to 20-char labels**: 1 day down to 1 hour.
//! - **21 to 62-char labels**: Baseline target time.
//!
//! # Inverse-Square Steal Decay Math
//!
//! When a name owner fails to publish regular heartbeats, the iteration effort required
//! for a third party to claim ("steal") the name decays via an inverse-square formula:
//!
//! $$\text{Multiplier} = \left(\frac{\text{steal\_target\_kyns}}{\text{kyns\_idle} + 1}\right)^2$$

/// Consensus parameters governing VDF difficulty and name takeover decay rates.
pub struct ConsensusParams {
    /// Number of Drand kyns a name must remain idle before takeover difficulty decays to $1\times$.
    pub steal_target_kyns: u64,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            steal_target_kyns: crate::constants::STEAL_TARGET_KYNS,
        }
    }
}

impl ConsensusParams {
    /// Returns the baseline hardware anchor iteration benchmark defined for the network.
    pub fn anchor(&self) -> u64 {
        crate::constants::BASE_ITERATIONS
    }

    /// Calculates the required VDF iterations for a full `.kin` name.
    ///
    /// Normalizes the name, extracts the apex label, and evaluates difficulty against the Name Difficulty Curve (NDC).
    ///
    /// # Examples
    ///
    /// ```
    /// use kinetic_core::consensus_math::ConsensusParams;
    ///
    /// let params = ConsensusParams::default();
    /// let iterations = params.iterations("example.kin");
    /// assert!(iterations > 0);
    /// ```
    pub fn iterations(&self, name: &str) -> u64 {
        let normalized_name = crate::types::names::normalize_name(name);
        let apex = crate::types::names::extract_apex_name(&normalized_name);
        let label = apex
            .strip_suffix(crate::constants::NSP_SUFFIX)
            .unwrap_or(&apex);
        self.label_iters(label)
    }

    /// Calculates required VDF iterations for a raw name label based on the Name Difficulty Curve (NDC).
    ///
    /// In dev mode (`is_dev_mode()`), returns a fixed low iteration count ([`DEV_MODE_ITERATIONS`](crate::constants::DEV_MODE_ITERATIONS)).
    pub fn label_iters(&self, label: &str) -> u64 {
        if crate::config::is_dev_mode() {
            return crate::constants::DEV_MODE_ITERATIONS;
        }

        let len = label.len();
        let base = self.anchor();
        let tm = crate::constants::TARGET_MINUTES as u64;

        // The configured NDC constants are absolute target times in minutes.
        // This closure scales the `base` iterations (which takes `tm` minutes)
        // to equal exactly `target_minutes` of sequential CPU work.
        let calc = |target_minutes: u64| -> u64 {
            ((base as u128 * target_minutes as u128) / tm as u128) as u64
        };

        // Name Difficulty Curve (NDC) dynamically adjusting to the hardware time target.
        // The constants passed in represent the raw target time in minutes.
        match len {
            0 | 1 => calc(crate::constants::CONSENSUS_NDC_LEN_0_TO_1), // 52,596,000 mins = 100 years
            2 => calc(crate::constants::CONSENSUS_NDC_LEN_2),          // 43,200 mins = 30 days
            3 => calc(crate::constants::CONSENSUS_NDC_LEN_3),          // 34,560 mins = 24 days
            4 => calc(crate::constants::CONSENSUS_NDC_LEN_4),          // 21,600 mins = 15 days
            5 => calc(crate::constants::CONSENSUS_NDC_LEN_5),          // 1,440 mins = 1 day
            6 => calc(crate::constants::CONSENSUS_NDC_LEN_6),          // 720 mins = 12 hours
            7 => calc(crate::constants::CONSENSUS_NDC_LEN_7),          // 150 mins = 2.5 hours
            8..=10 => calc(crate::constants::CONSENSUS_NDC_LEN_8_TO_10), // 120 mins = 2 hours
            11..=17 => calc(crate::constants::CONSENSUS_NDC_LEN_11_TO_17), // 90 mins = 1.5 hours
            18..=20 => calc(crate::constants::CONSENSUS_NDC_LEN_18_TO_20), // 60 mins = 1 hour
            21..=63 => base, // Baseline (always takes exactly `tm` minutes)
            _ => base,       // Fallback
        }
    }

    /// Calculates the VDF iteration effort required to claim an idle name.
    ///
    /// Applies an inverse-square multiplier based on `kyns_idle`. As `kyns_idle` increases,
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
    /// let diff_early = params.steal_diff(base, 100);
    /// assert!(diff_early >= base);
    /// ```
    #[allow(clippy::comparison_chain)]
    pub fn steal_diff(&self, base_iterations: u64, kyns_idle: u64) -> u64 {
        let idle_plus = kyns_idle.saturating_add(1) as u128;
        let target_kyns = self.steal_target_kyns as u128;

        let multiplier = if target_kyns > idle_plus {
            let target_sq = target_kyns * target_kyns;
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
        let a = params.iterations("a");
        let ab = params.iterations("ab");
        let abc = params.iterations("abc");

        if crate::config::is_dev_mode() {
            assert_eq!(a, crate::constants::DEV_MODE_ITERATIONS);
            assert_eq!(ab, crate::constants::DEV_MODE_ITERATIONS);
            assert_eq!(abc, crate::constants::DEV_MODE_ITERATIONS);
        } else {
            assert!(a > ab);
            assert!(ab > abc);
        }
    }

    // Hardware drift is managed manually via network updates.

    #[test]
    fn test_steal_difficulty() {
        let params = ConsensusParams::default();
        let target = params.steal_target_kyns;

        let diff_early = params.steal_diff(100, target / 2);
        assert!(diff_early > 100); // 4x multiplier

        let diff_late = params.steal_diff(100, target * 2);
        assert_eq!(diff_late, 100); // 1x multiplier (min)
    }
}
