//! Protocol action subsystem bindings.
//!
//! This module re-exports types and functions from the decoupled `kinetic-action` crate,
//! bridging it with `kinetic-core` configurations for ease of use across the workspace.

pub use kinetic_action::error::ActionError;
pub use kinetic_action::traits::ActionEngine;
pub use kinetic_action::types;
pub use kinetic_action::types::{
    NetworkAction, ActionEffect, ActionState, SignedActionMessage, verify_signature,
};

/// Wraps logic bindings that require configurations.
pub mod logic {
    use super::*;

    /// Validates that the static cryptographic keys required for action have been correctly initialized.
    pub fn validate_keys_initialized() -> Result<(), ActionError> {
        kinetic_action::logic::validate_keys_initialized(
            crate::constants::SOVEREIGN_KEY_HEX,
            crate::config::is_dev_mode(),
        )
    }
}

use kinetic_action::types::ActionConfig;

/// Constructs the action configuration based on network constants.
pub fn get_action_config() -> ActionConfig {
    ActionConfig {
        sovereign_key_hex: crate::constants::SOVEREIGN_KEY_HEX.to_string(),
        max_age_kyns: crate::constants::MAX_AGE_KYNS,
        is_dev_mode: crate::config::is_dev_mode(),
        action_model: crate::constants::ACTION_MODEL.to_string(),
    }
}

/// Processes a action message by passing the network configurations automatically.
pub fn process_action_message(
    state: &mut ActionState,
    msg: &SignedActionMessage,
    current_kyn: kinetic_types::clock::Kyn,
) -> Result<Option<ActionEffect>, ActionError> {
    kinetic_action::logic::process_action_message(
        state,
        msg,
        current_kyn,
        &get_action_config(),
    )
}
