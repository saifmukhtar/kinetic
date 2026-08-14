//! Kinetic Network Timekeeping & Branded Time Units.
//!
//! Provides branded time tracking for frontends, explorers, and node monitoring.
//! The underlying consensus engine uses absolute network beacons, which this module
//! translates into the official Kinetic time hierarchy (The Crystal Lexicon):
//!
//! - **1 Kyn** = 3 seconds (The atomic heartbeat)
//! - **1 Facet** = 1,200 Kyns (1 Hour)
//! - **1 Prism** = 28,800 Kyns (1 Day / 24 Hours)
//! - **1 Matrix** = 7 Prisms (1 Week / 7 Days / 201,600 Kyns)
//! - **1 Lattice** = 30 Prisms (1 Month / 30 Days / 864,000 Kyns)
//! - **1 Aeon** = 365 Prisms (1 Year / 365 Days / 10,512,000 Kyns)

pub use kinetic_types::clock::{KineticTime, kyn_to_unix_secs, unix_secs_to_kyn};

/// Converts an absolute Drand kyn to deterministic Unix epoch seconds using network constants.
#[inline]
pub fn network_kyn_to_unix_secs(kyn: u64) -> u64 {
    kyn_to_unix_secs(
        kyn,
        crate::constants::DRAND_GENESIS_TIME,
        crate::constants::DRAND_PERIOD,
    )
}

/// Converts a Unix timestamp (in seconds) to an estimated network Drand kyn using network constants.
#[inline]
pub fn unix_secs_to_network_kyn(unix_secs: u64) -> u64 {
    unix_secs_to_kyn(
        unix_secs,
        crate::constants::DRAND_GENESIS_TIME,
        crate::constants::DRAND_PERIOD,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::KINETIC_GENESIS_DRAND_KYN;

    // Note: KINETIC_GENESIS_DRAND_KYN is defined in network.json / build.rs.
    // For these tests, we assume it acts correctly regardless of its exact value,
    // by manually shifting our input by the genesis kyn.

    #[test]
    fn test_kinetic_time_zero() {
        let genesis = KINETIC_GENESIS_DRAND_KYN;
        let time = KineticTime::from_kyn(genesis, genesis);
        assert_eq!(time.prism, 0);
        assert_eq!(time.facet, 0);
        assert_eq!(time.kyn, 0);
        assert_eq!(time.total_kyns, 0);
    }

    #[test]
    #[allow(clippy::absurd_extreme_comparisons)]
    fn test_kinetic_time_pre_genesis() {
        if KINETIC_GENESIS_DRAND_KYN > 0 {
            let time =
                KineticTime::from_kyn(KINETIC_GENESIS_DRAND_KYN - 1, KINETIC_GENESIS_DRAND_KYN);
            assert_eq!(time.total_kyns, 0);
        }
    }

    #[test]
    fn test_kinetic_time_complex() {
        let genesis = KINETIC_GENESIS_DRAND_KYN;

        // 1 day (28,800) + 2 hours (2,400) + 45 kyns = 31,245 total kyns
        let target_kyn = genesis + 31_245;
        let time = KineticTime::from_kyn(target_kyn, genesis);

        assert_eq!(time.prism, 1);
        assert_eq!(time.facet, 2);
        assert_eq!(time.kyn, 45);
        assert_eq!(time.total_kyns, 31_245);
    }

    #[test]
    fn test_network_kyn_unix_conversion() {
        let kyn = 30_579_969;
        let unix_secs = network_kyn_to_unix_secs(kyn);
        assert_eq!(
            unix_secs,
            crate::constants::DRAND_GENESIS_TIME + (kyn * crate::constants::DRAND_PERIOD)
        );
        let recovered = unix_secs_to_network_kyn(unix_secs);
        assert_eq!(recovered, kyn);
    }
}
