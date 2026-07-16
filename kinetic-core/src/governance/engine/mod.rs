pub mod anarchy;
pub mod bicameral;
pub mod monarchy;
pub mod council;

use crate::traits::GovernanceEngine;

/// Returns the active governance engine based on the build-time configuration.
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
