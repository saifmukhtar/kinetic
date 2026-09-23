//! Kinetic Network Timekeeping & Branded Time Units.
//!
//! Provides branded time tracking for frontends, explorers, and node monitoring.
//! The underlying consensus engine uses absolute network beacons, which this module
//! translates into the official Kinetic time hierarchy (The Crystal Lexicon):
//!
//! - **1 Kyn** = 1 Second (The atomic age of the network since genesis)
//! - **1 Facet** = 3,600 Kyns (1 Hour)
//! - **1 Prism** = 86,400 Kyns (1 Day / 24 Hours)
//!
//! Higher-order units (Matrix, Lattice, Aeon) are derivable from `prism` by the
//! caller and are intentionally omitted from this type to keep it a pure data contract.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Strict type for Unix Time in seconds.
///
/// This wrapper prevents accidental math operations between network `Kyn` units 
/// and local wall-clock seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UKyn(pub u64);

/// Strict type for an absolute Kinetic Network Time `Kyn`.
///
/// A `Kyn` represents a verified tick representing 1 second of network age. 
/// Because it is mathematically proven, it is the only safe unit of time for 
/// protocol-level validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Kyn(pub u64);

macro_rules! define_nested_kyns {
    ( $(
        $(#[$meta:meta])*
        $type_name:ident
    ),* ) => {
        $(
            $(#[$meta])*
            #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
            #[serde(transparent)]
            pub struct $type_name(pub Kyn);

            impl $type_name {
                /// Extracts the raw u64 network tick directly.
                pub fn as_u64(&self) -> u64 {
                    (self.0).0
                }
            }

            impl std::ops::Deref for $type_name {
                type Target = Kyn;
                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }

            impl From<Kyn> for $type_name {
                fn from(kyn: Kyn) -> Self {
                    Self(kyn)
                }
            }
            
            impl From<u64> for $type_name {
                fn from(val: u64) -> Self {
                    Self(Kyn(val))
                }
            }

            impl fmt::Display for $type_name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "{}", (self.0).0)
                }
            }
        )*
    };
}

define_nested_kyns! {
    /// A cryptographic target or mathematical seed bound to a specific Kyn.
    TargetKyn,
    /// A point-in-time timestamp representing when an action occurred.
    TimestampKyn,
    /// The absolute genesis point of the network.
    GenesisKyn,
    /// A timestamp marking when an emergency network halt began.
    HaltStartKyn,
    /// The current Kyn of the local network state (merged with LatestKyn).
    CurrentKyn,
    /// A deadline or expiration threshold.
    ExpiryKyn,
    /// The starting Kyn of a specific operational window (merged with FromKyn).
    StartKyn,
    /// The ending Kyn of a specific operational window.
    EndKyn,
    /// The Kyn representing a session's initialization.
    InitialKyn
}

/// Represents a specific point in time on the Kinetic network using branded units.
///
/// # Time Hierarchy
///
/// - **Kyn**: 1 Second
/// - **Facet**: 3,600 Kyns (1 Hour)
/// - **Prism**: 86,400 Kyns (1 Day)
///
/// Higher-order units (Matrix = 7 Prisms, Lattice = 30 Prisms, Aeon = 365 Prisms)
/// are intentionally not provided as methods — callers derive them from `prism` directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrystallizedKyn {
    /// Number of completed 24-hour network Prisms (86,400 kyns each).
    pub prism: u64,
    /// Number of completed 1-hour network Facets within the current Prism (3,600 kyns each, 0..23).
    pub facet: u64,
    /// Number of completed 1-second Kyns within the current Facet (0..3599).
    pub kyn: u64,
    /// Total number of kyns elapsed since network genesis.
    pub total: u64,
}

impl fmt::Display for UKyn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for Kyn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


