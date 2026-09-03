//! Governance engine trait drivers for different network decision-making models.
//!
//! Provides concrete implementations of the [`GovernanceEngine`](crate::traits::GovernanceEngine)
//! trait, which define the signature thresholds for protocol actions.

pub mod permissionless;
pub mod sovereign;

use crate::traits::GovernanceEngine;

/// Returns the active governance engine driver based on the configuration.
///
/// # Returns
///
/// A static reference to the selected [`GovernanceEngine`](crate::traits::GovernanceEngine).
///
/// # Panics
///
/// Panics if an unknown model is specified.
pub fn get_active_engine(model: &str) -> &'static dyn GovernanceEngine {
    match model {
        "sovereign" => &sovereign::SovereignEngine,
        "permissionless" => &permissionless::PermissionlessEngine,
        _ => panic!("Unknown governance model '{}' specified", model),
    }
}
