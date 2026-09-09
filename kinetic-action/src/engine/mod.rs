//! Governance engine trait drivers for different network decision-making models.
//!
//! Provides concrete implementations of the [`ActionEngine`](crate::traits::ActionEngine)
//! trait, which define the signature thresholds for protocol actions.

pub mod permissionless;
pub mod sovereign;

use crate::traits::ActionEngine;

/// Returns the active governance engine driver based on the configuration.
///
/// # Returns
///
/// A static reference to the selected [`ActionEngine`](crate::traits::ActionEngine).
///
/// # Panics
///
/// Panics if an unknown model is specified.
pub fn get_active_engine(model: &str) -> &'static dyn ActionEngine {
    match model {
        "sovereign" => &sovereign::SovereignEngine,
        "permissionless" => &permissionless::PermissionlessEngine,
        _ => panic!("Unknown governance model '{}' specified", model),
    }
}
