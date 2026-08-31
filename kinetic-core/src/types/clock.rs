//! Kinetic Network Timekeeping & Branded Time Units.
//!
//! Provides branded time tracking for frontends, explorers, and node monitoring.
//! The underlying consensus engine uses absolute network beacons, which this module
//! translates into the official Kinetic time hierarchy (The Crystal Lexicon).

pub use kinetic_types::clock::{Kyn, UTime, KineticTime};
use crate::constants::{DRAND_GENESIS_TIME, DRAND_PERIOD};

/// Extension trait that adds network-aware conversions to the pure math clock types.
pub trait NetworkClockExt {
    /// Converts a Drand kyn into deterministic Unix epoch seconds using local network constants.
    fn to_network_utime(&self) -> UTime;
}

impl NetworkClockExt for Kyn {
    #[inline]
    fn to_network_utime(&self) -> UTime {
        self.to_utime(DRAND_GENESIS_TIME, DRAND_PERIOD)
    }
}

/// Extension trait for estimating network kyns from Unix time.
pub trait UTimeNetworkExt {
    /// Converts a Unix timestamp into an estimated network Drand kyn using local network constants.
    fn to_network_kyn(&self) -> Kyn;
}

impl UTimeNetworkExt for UTime {
    #[inline]
    fn to_network_kyn(&self) -> Kyn {
        self.to_kyn(DRAND_GENESIS_TIME, DRAND_PERIOD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::KINETIC_GENESIS_KYN;

    #[test]
    fn test_kinetic_time_zero() {
        let genesis = Kyn(KINETIC_GENESIS_KYN);
        let time = KineticTime::from_kyn(genesis, genesis);
        assert_eq!(time.prism, 0);
        assert_eq!(time.facet, 0);
        assert_eq!(time.kyn, 0);
        assert_eq!(time.total_kyns, 0);
    }

    #[test]
    fn test_kinetic_time_pre_genesis() {
        if KINETIC_GENESIS_KYN > 0 {
            let time =
                KineticTime::from_kyn(Kyn(KINETIC_GENESIS_KYN - 1), Kyn(KINETIC_GENESIS_KYN));
            assert_eq!(time.total_kyns, 0);
        }
    }

    #[test]
    fn test_kinetic_time_complex() {
        let genesis = Kyn(KINETIC_GENESIS_KYN);

        // 1 day (28,800) + 2 hours (2,400) + 45 kyns = 31,245 total kyns
        let target_kyn = Kyn(KINETIC_GENESIS_KYN + 31_245);
        let time = KineticTime::from_kyn(target_kyn, genesis);

        assert_eq!(time.prism, 1);
        assert_eq!(time.facet, 2);
        assert_eq!(time.kyn, 45);
        assert_eq!(time.total_kyns, 31_245);
    }

    #[test]
    fn test_network_kyn_unix_conversion() {
        let kyn = Kyn(30_579_969);
        let unix_secs = kyn.to_network_utime();
        assert_eq!(
            unix_secs,
            UTime(crate::constants::DRAND_GENESIS_TIME + (kyn.0 * crate::constants::DRAND_PERIOD))
        );
        let recovered = unix_secs.to_network_kyn();
        assert_eq!(recovered, kyn);
    }
}
