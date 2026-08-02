//! Kinetic Network Timekeeping & Branded Time Units.
//!
//! Provides branded time tracking for frontends, explorers, and node monitoring.
//! The underlying consensus engine uses absolute Drand rounds, which this module
//! translates into the official Kinetic time hierarchy:
//!
//! - **1 Pulse** = 1 Drand Round (3 seconds)
//! - **1 Cycle** = 1,200 Pulses (1 Hour)
//! - **1 Epoch** = 28,800 Pulses (1 Day / 24 Hours)
//! - **1 Orbit** = 7 Epochs (1 Week / 7 Days / 201,600 Pulses)


pub use kinetic_types::clock::KineticTime;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::KINETIC_GENESIS_DRAND_ROUND;

    // Note: KINETIC_GENESIS_DRAND_ROUND is defined in network.json / build.rs.
    // For these tests, we assume it acts correctly regardless of its exact value,
    // by manually shifting our input by the genesis round.

    #[test]
    fn test_kinetic_time_zero() {
        let genesis = KINETIC_GENESIS_DRAND_ROUND;
        let time = KineticTime::from_drand_round(genesis, genesis);
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
            let time = KineticTime::from_drand_round(KINETIC_GENESIS_DRAND_ROUND - 1, KINETIC_GENESIS_DRAND_ROUND);
            assert_eq!(time.total_pulses, 0);
        }
    }

    #[test]
    fn test_kinetic_time_complex() {
        let genesis = KINETIC_GENESIS_DRAND_ROUND;

        // 1 day (28,800) + 2 hours (2,400) + 45 pulses = 31,245 total pulses
        let target_round = genesis + 31_245;
        let time = KineticTime::from_drand_round(target_round, genesis);

        assert_eq!(time.epoch, 1);
        assert_eq!(time.cycle, 2);
        assert_eq!(time.pulse, 45);
        assert_eq!(time.total_pulses, 31_245);
        assert_eq!(time.to_display_string(), "Epoch 1, Cycle 2 (Pulse 45)");
    }
}
