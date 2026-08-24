//! Governance engine trait drivers for different network decision-making models.
//!
//! Provides concrete implementations of the [`GovernanceEngine`](crate::traits::GovernanceEngine)
//! trait, which define the signature thresholds for protocol actions.

pub mod permissionless;
pub mod sovereign;

use crate::traits::GovernanceEngine;

/// Returns the active governance engine driver based on the compile-time configuration.
///
/// # Returns
///
/// A static reference to the selected [`GovernanceEngine`](crate::traits::GovernanceEngine).
///
/// # Panics
///
/// Panics at startup if `GOVERNANCE_MODEL` in `network.json` is set to an unknown value.
pub fn get_active_engine() -> &'static dyn GovernanceEngine {
    match crate::constants::GOVERNANCE_MODEL {
        "sovereign" => &sovereign::SovereignEngine,
        "permissionless" => &permissionless::PermissionlessEngine,
        _ => panic!(
            "Unknown governance model '{}' specified in network.json",
            crate::constants::GOVERNANCE_MODEL
        ),
    }
}
