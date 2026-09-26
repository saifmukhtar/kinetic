//! Network action engine trait drivers for different decision-making models.
//!
//! Provides concrete implementations of the [`ActionEngine`] trait,
//! which define the signature rules for network actions.

pub mod permissionless;
pub mod sovereign;

use crate::traits::ActionEngine;

/// Returns the active network action engine driver based on the configuration.
///
/// # Returns
///
/// A boxed instance of the selected [`ActionEngine`].
///
/// # Panics
///
/// Panics if an unknown model is specified.
pub fn active_engine(model: &str) -> Box<dyn ActionEngine> {
    match model {
        "sovereign" => Box::new(sovereign::SovereignEngine),
        "permissionless" => Box::new(permissionless::PermissionlessEngine),
        _ => panic!("Unknown action model '{}' specified", model),
    }
}
