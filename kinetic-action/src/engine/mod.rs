//! Action engine trait drivers for different network decision-making models.
//!
//! Provides concrete implementations of the [`ActionEngine`](crate::traits::ActionEngine)
//! trait, which define the signature thresholds for protocol actions.

pub mod permissionless;
pub mod sovereign;

use crate::traits::ActionEngine;

/// Returns the active action engine driver based on the configuration.
///
/// # Returns
///
/// A boxed instance of the selected [`ActionEngine`](crate::traits::ActionEngine).
///
/// # Panics
///
/// Panics if an unknown model is specified.
pub fn get_active_engine(model: &str) -> Box<dyn ActionEngine> {
    match model {
        "sovereign" => Box::new(sovereign::SovereignEngine),
        "permissionless" => Box::new(permissionless::PermissionlessEngine),
        _ => panic!("Unknown action model '{}' specified", model),
    }
}
