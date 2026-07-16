//! Kinetic Timekeeping
//!
//! Provides purely cosmetic, branded time tracking for frontends and block explorers.
//! The underlying consensus engine uses absolute Drand rounds, but this module
//! translates those rounds into the official Kinetic Epoch/Cycle/Pulse format.

use crate::constants::KINETIC_GENESIS_DRAND_ROUND;
use serde::{Deserialize, Serialize};

/// Represents a specific point in time on the Kinetic network using branded units.
///
/// - 1 Pulse = 1 Drand Round (3 seconds)
/// - 1 Cycle = 1,200 Pulses (1 Hour)
/// - 1 Epoch = 28,800 Pulses (1 Day)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KineticTime {
    pub epoch: u64,
    pub cycle: u64,
    pub pulse: u64,
    pub total_pulses: u64,
}

impl KineticTime {
    /// Creates a new `KineticTime` from an absolute Drand round.
    ///
    /// If the provided round is before the `KINETIC_GENESIS_DRAND_ROUND`, it returns a time of zero.
    #[allow(clippy::absurd_extreme_comparisons)]
    pub fn from_drand_round(current_drand_round: u64) -> Self {
        if current_drand_round < KINETIC_GENESIS_DRAND_ROUND {
            return Self {
                epoch: 0,
                cycle: 0,
                pulse: 0,
                total_pulses: 0,
            };
        }

        let total_pulses = current_drand_round - KINETIC_GENESIS_DRAND_ROUND;

        let epoch = total_pulses / 28_800;
        let remainder_after_epoch = total_pulses % 28_800;

        let cycle = remainder_after_epoch / 1_200;
        let pulse = remainder_after_epoch % 1_200;

        Self {
            epoch,
            cycle,
            pulse,
            total_pulses,
        }
    }

    /// Formats the time as a sleek, sci-fi aesthetic string.
    /// Example: `Epoch 14, Cycle 8 (Pulse 452)`
    pub fn to_display_string(&self) -> String {
        format!(
            "Epoch {}, Cycle {} (Pulse {})",
            self.epoch, self.cycle, self.pulse
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: KINETIC_GENESIS_DRAND_ROUND is defined in network.json / build.rs.
    // For these tests, we assume it acts correctly regardless of its exact value,
    // by manually shifting our input by the genesis round.

    #[test]
    fn test_kinetic_time_zero() {
        let genesis = KINETIC_GENESIS_DRAND_ROUND;
        let time = KineticTime::from_drand_round(genesis);
        assert_eq!(time.epoch, 0);
        assert_eq!(time.cycle, 0);
        assert_eq!(time.pulse, 0);
        assert_eq!(time.total_pulses, 0);
        assert_eq!(time.to_display_string(), "Epoch 0, Cycle 0 (Pulse 0)");
    }

    #[test]
    #[allow(clippy::absurd_extreme_comparisons)]
    fn test_kinetic_time_pre_genesis() {
        if KINETIC_GENESIS_DRAND_ROUND > 0 {
            let time = KineticTime::from_drand_round(KINETIC_GENESIS_DRAND_ROUND - 1);
            assert_eq!(time.total_pulses, 0);
        }
    }

    #[test]
    fn test_kinetic_time_complex() {
        let genesis = KINETIC_GENESIS_DRAND_ROUND;

        // 1 day (28,800) + 2 hours (2,400) + 45 pulses = 31,245 total pulses
        let target_round = genesis + 31_245;
        let time = KineticTime::from_drand_round(target_round);

        assert_eq!(time.epoch, 1);
        assert_eq!(time.cycle, 2);
        assert_eq!(time.pulse, 45);
        assert_eq!(time.total_pulses, 31_245);
        assert_eq!(time.to_display_string(), "Epoch 1, Cycle 2 (Pulse 45)");
    }
}
