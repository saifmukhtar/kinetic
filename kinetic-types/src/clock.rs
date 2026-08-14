//! Kinetic Network Timekeeping & Branded Time Units.
//!
//! Provides branded time tracking for frontends, explorers, and node monitoring.
//! The underlying consensus engine uses absolute network beacons, which this module
//! translates into the official Kinetic time hierarchy (The Crystal Lexicon):
//!
//! - **1 Kyn** = 3 seconds (The atomic heartbeat)
//! - **1 Facet** = 1,200 Kyns (1 Hour)
//! - **1 Prism** = 28,800 Kyns (1 Day / 24 Hours)
//!
//! Higher-order units (Matrix, Lattice, Aeon) are derivable from `prism` by the
//! caller and are intentionally omitted from this type to keep it a pure data contract.

use serde::{Deserialize, Serialize};

/// Represents a specific point in time on the Kinetic network using branded units.
///
/// # Time Hierarchy
///
/// - **Kyn**: 3 seconds
/// - **Facet**: 1,200 Kyns (1 Hour)
/// - **Prism**: 28,800 Kyns (1 Day)
///
/// Higher-order units (Matrix = 7 Prisms, Lattice = 30 Prisms, Aeon = 365 Prisms)
/// are intentionally not provided as methods — callers derive them from `prism` directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KineticTime {
    /// Number of completed 24-hour network Prisms (28,800 kyns each).
    pub prism: u64,
    /// Number of completed 1-hour network Facets within the current Prism (1,200 kyns each, 0..23).
    pub facet: u64,
    /// Number of completed 3-second Kyns within the current Facet (0..1199).
    pub kyn: u64,
    /// Total number of kyns elapsed since network genesis.
    pub total_kyns: u64,
}

impl KineticTime {
    /// Creates a new [`KineticTime`] instance from an absolute network kyn number and a genesis kyn.
    ///
    /// If `current_kyn` is less than `genesis_kyn`,
    /// returns a time structure initialized to zero.
    // `current_kyn < genesis_kyn` is a valid safety guard even though both operands are
    // unsigned — Drand can return a stale kyn that predates network genesis during initial
    // sync. Clippy flags this comparison as absurd on u64 because it can never be negative,
    // but the guard is intentional and correct. Suppressed to avoid a misleading warning.
    #[allow(clippy::absurd_extreme_comparisons)]
    pub fn from_kyn(current_kyn: u64, genesis_kyn: u64) -> Self {
        if current_kyn < genesis_kyn {
            return Self {
                prism: 0,
                facet: 0,
                kyn: 0,
                total_kyns: 0,
            };
        }

        let total_kyns = current_kyn - genesis_kyn;

        let prism = total_kyns / 28_800;
        let remainder_after_prism = total_kyns % 28_800;

        let facet = remainder_after_prism / 1_200;
        let kyn = remainder_after_prism % 1_200;

        // Safety invariants: integer division guarantees these ranges, but asserting
        // them in debug builds catches any future refactor that breaks the arithmetic.
        debug_assert!(facet < 24, "facet must be in 0..23, got {facet}");
        debug_assert!(kyn < 1_200, "kyn must be in 0..1199, got {kyn}");

        Self {
            prism,
            facet,
            kyn,
            total_kyns,
        }
    }
}

/// Converts an absolute Drand kyn number to deterministic Unix epoch seconds.
///
/// Uses saturating arithmetic. Overflow would require `kyn × period > u64::MAX`
/// (~570 billion years at a 3-second period) and is physically impossible in practice.
/// On overflow the result silently saturates to `u64::MAX` rather than panicking.
#[inline]
pub fn kyn_to_unix_secs(kyn: u64, drand_genesis_time: u64, drand_period: u64) -> u64 {
    drand_genesis_time.saturating_add(kyn.saturating_mul(drand_period))
}

/// Converts a Unix timestamp (in seconds) to the corresponding absolute Drand kyn number.
#[inline]
pub fn unix_secs_to_kyn(unix_secs: u64, drand_genesis_time: u64, drand_period: u64) -> u64 {
    if drand_period == 0 {
        return 0;
    }
    // Integer division intentionally truncates sub-period remainder — if `unix_secs`
    // falls between two beacon rounds, this returns the floor (last confirmed) kyn.
    // This is the correct behavior for consensus: always use the last verified beacon.
    unix_secs.saturating_sub(drand_genesis_time) / drand_period
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyn_unix_conversion_roundtrip() {
        // Test fixture values — deliberately not tied to any real Drand network config.
        // The math is network-agnostic; only the period unit (3 s) is meaningful here.
        let genesis_time: u64 = 1_000;
        let period: u64 = 3;
        let kyn: u64 = 500;

        let unix_secs = kyn_to_unix_secs(kyn, genesis_time, period);
        assert_eq!(unix_secs, genesis_time + (kyn * period));

        let recovered_kyn = unix_secs_to_kyn(unix_secs, genesis_time, period);
        assert_eq!(recovered_kyn, kyn);
    }

    #[test]
    fn test_unix_secs_to_kyn_zero_period() {
        assert_eq!(unix_secs_to_kyn(100, 50, 0), 0);
    }

    #[test]
    fn test_from_kyn_boundaries() {
        let genesis = 1000;

        // Before genesis
        let t1 = KineticTime::from_kyn(999, genesis);
        assert_eq!(t1.total_kyns, 0);

        // Exactly genesis
        let t2 = KineticTime::from_kyn(1000, genesis);
        assert_eq!((t2.prism, t2.facet, t2.kyn, t2.total_kyns), (0, 0, 0, 0));

        // 1 Kyn later
        let t3 = KineticTime::from_kyn(1001, genesis);
        assert_eq!((t3.prism, t3.facet, t3.kyn, t3.total_kyns), (0, 0, 1, 1));

        // Exactly 1 Facet (1,200 kyns)
        let t4 = KineticTime::from_kyn(1000 + 1200, genesis);
        assert_eq!((t4.prism, t4.facet, t4.kyn, t4.total_kyns), (0, 1, 0, 1200));

        // Exactly 1 Prism (28,800 kyns)
        let t5 = KineticTime::from_kyn(1000 + 28800, genesis);
        assert_eq!(
            (t5.prism, t5.facet, t5.kyn, t5.total_kyns),
            (1, 0, 0, 28800)
        );

        // Complex time: 1 Prism + 2 Facets + 3 Kyns = 28800 + 2400 + 3 = 31203
        let t6 = KineticTime::from_kyn(1000 + 31203, genesis);
        assert_eq!(
            (t6.prism, t6.facet, t6.kyn, t6.total_kyns),
            (1, 2, 3, 31203)
        );
    }

    #[test]
    fn test_large_epochs() {
        let genesis = 0;

        // 1 Matrix = 7 Prisms = 7 × 28,800 = 201,600 kyns
        let t_matrix = KineticTime::from_kyn(201_600, genesis);
        assert_eq!(t_matrix.prism / 7, 1);

        // 1 Lattice = 30 Prisms = 30 × 28,800 = 864,000 kyns
        let t_lattice = KineticTime::from_kyn(864_000, genesis);
        assert_eq!(t_lattice.prism / 30, 1);

        // 1 Aeon = 365 Prisms = 365 × 28,800 = 10,512,000 kyns
        let t_aeon = KineticTime::from_kyn(10_512_000, genesis);
        assert_eq!(t_aeon.prism / 365, 1);
    }
}
