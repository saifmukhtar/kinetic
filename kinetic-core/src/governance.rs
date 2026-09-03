//! Protocol governance subsystem bindings.
//!
//! This module re-exports types and functions from the decoupled `kinetic-action` crate,
//! bridging it with `kinetic-core` configurations for ease of use across the workspace.

pub use kinetic_action::error::GovernanceError;
pub use kinetic_action::traits::GovernanceEngine;
pub use kinetic_action::types;
pub use kinetic_action::types::{
    GovernanceAction, GovernanceEffect, GovernanceState, SignedGovernanceMessage, verify_signature,
};

/// Wraps logic bindings that require configurations.
pub mod logic {
    use super::*;

    /// Validates that the static cryptographic keys required for governance have been correctly initialized.
    pub fn validate_keys_initialized() -> Result<(), GovernanceError> {
        kinetic_action::logic::validate_keys_initialized(
            crate::constants::SOVEREIGN_KEY_HEX,
            crate::config::is_dev_mode(),
        )
    }
}

use kinetic_action::types::GovernanceConfig;

/// Constructs the governance configuration based on network constants.
pub fn get_governance_config() -> GovernanceConfig {
    GovernanceConfig {
        sovereign_key_hex: crate::constants::SOVEREIGN_KEY_HEX.to_string(),
        max_age_kyns: crate::constants::MAX_AGE_KYNS,
        is_dev_mode: crate::config::is_dev_mode(),
        governance_model: crate::constants::GOVERNANCE_MODEL.to_string(),
    }
}

/// Processes a governance message by passing the network configurations automatically.
pub fn process_governance_message(
    state: &mut GovernanceState,
    msg: &SignedGovernanceMessage,
    current_kyn: kinetic_types::clock::Kyn,
) -> Result<Option<GovernanceEffect>, GovernanceError> {
    kinetic_action::logic::process_governance_message(
        state,
        msg,
        current_kyn,
        &get_governance_config(),
    )
}
