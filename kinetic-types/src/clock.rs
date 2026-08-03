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
//! - **1 Apex** = 365 Prisms (1 Year / 365 Days / 10,512,000 Kyns)

use serde::{Deserialize, Serialize};

/// Represents a specific point in time on the Kinetic network using branded units.
///
/// # Time Hierarchy
///
/// - **Kyn**: 3 seconds
/// - **Facet**: 1,200 Kyns (1 Hour)
/// - **Prism**: 28,800 Kyns (1 Day)
/// - **Matrix**: 7 Prisms (1 Week)
/// - **Lattice**: 30 Prisms (1 Month)
/// - **Apex**: 365 Prisms (1 Year)
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

        Self {
            prism,
            facet,
            kyn,
            total_kyns,
        }
    }

    /// Returns the number of completed 7-day network Matrices (1 Matrix = 7 Prisms).
    pub fn matrix(&self) -> u64 {
        self.prism / 7
    }

    /// Returns the number of completed 30-day network Lattices (1 Lattice = 30 Prisms).
    pub fn lattice(&self) -> u64 {
        self.prism / 30
    }

    /// Returns the number of completed 365-day network Apexes (1 Apex = 365 Prisms).
    pub fn apex(&self) -> u64 {
        self.prism / 365
    }

    /// Formats the time into a branded aesthetic string.
    pub fn to_display_string(&self) -> String {
        format!(
            "Prism {}, Facet {} (Kyn {})",
            self.prism, self.facet, self.kyn
        )
    }
}
