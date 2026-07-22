//! Governance engine trait drivers for different network decision-making models.
//!
//! Provides concrete implementations of the [`GovernanceEngine`](crate::traits::GovernanceEngine)
//! trait, which define the signature thresholds and timelock requirements for protocol actions.

pub mod anarchy;
pub mod bicameral;
pub mod council;
pub mod monarchy;

use crate::traits::GovernanceEngine;

/// Returns the active governance engine driver based on the compile-time configuration.
///
/// # Returns
///
/// A boxed heap-allocated instance of the selected [`GovernanceEngine`](crate::traits::GovernanceEngine).
///
/// # Panics
///
/// Panics at startup if `GOVERNANCE_MODEL` in `network.json` is set to an unknown value.
pub fn get_active_engine() -> Box<dyn GovernanceEngine> {
    match crate::constants::GOVERNANCE_MODEL {
        "bicameral" => Box::new(bicameral::BicameralEngine),
        "monarchy" => Box::new(monarchy::MonarchyEngine),
        "anarchy" => Box::new(anarchy::AnarchyEngine),
        "council" => Box::new(council::CouncilEngine),
        _ => panic!(
            "Unknown governance model '{}' specified in network.json",
            crate::constants::GOVERNANCE_MODEL
        ),
    }
}
