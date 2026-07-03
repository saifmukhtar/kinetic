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
        80, 211, 223, 74, 91, 155, 132, 168, 78, 209, 214, 167, 237, 160, 157, 186, 48, 9, 140, 185, 74, 172, 136, 188, 246, 164, 147, 64, 96, 11, 197, 62
    ]);

    /// The exact list of names the Genesis Key is allowed to claim.
    pub const GENESIS_ALLOWLIST: [&'static str; 39] = [
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
        "seed",
        "seed1",
        "seed2",
        "api",
        "cdn",
        "registry",
        "id",
        "identity",
        "app",
        "www",
        "wallet",
        "pay",
        "code",
        "git",
        "status",
        "dao",
        "gov",
        "foundation",
        "localhost",
        "local",
        "support",
        "help",
    ];

    /// The Drand pulse when the network launches.
    pub const GENESIS_START_PULSE: u64 = 10_900_000; // Aligned with recent Quicknet rounds for launch

    /// Finding 11: Genesis key expiry. After this pulse, the genesis key receives NO special
    /// VDF exemption and must compete on equal terms. ~6 months at 3s/round (Quicknet).
    /// 6 months = 180 days * 24h * 3600s / 3s = 5,184,000 rounds.
    pub const GENESIS_EXPIRY_PULSE: u64 = Self::GENESIS_START_PULSE + 5_184_000;

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
                // Finding 11: Genesis key privilege expires after GENESIS_EXPIRY_PULSE.
                // After that round, it must compute the same VDF as everyone else.
                if pubkey == genesis_pk && current_round < Self::GENESIS_EXPIRY_PULSE {
                    return 10_000;
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

        // Genesis key gets 10,000 iterations for allowlisted names before expiry.
        let iters_at_launch =
            params.required_iterations("saif.kin", ConsensusParams::GENESIS_START_PULSE, &pk);
        assert_eq!(iters_at_launch, 10000);

        // Still 10000 well within the expiry window.
        let iters_later = params.required_iterations(
            "saif.kin",
            ConsensusParams::GENESIS_START_PULSE + 1_000_000,
            &pk,
        );
        assert_eq!(iters_later, 10000);

        // Finding 11: After GENESIS_EXPIRY_PULSE, genesis key gets no exemption.
        let iters_expired = params.required_iterations(
            "saif.kin",
            ConsensusParams::GENESIS_EXPIRY_PULSE + 1,
            &pk,
        );
        assert!(iters_expired > 10000, "Genesis key must compute full VDF after expiry");

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
