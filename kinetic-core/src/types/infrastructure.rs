/// Category 2: Kinetic Infrastructure Names
/// These names represent critical network infrastructure (docs, bootstrap nodes, explorer).
/// To prevent squatters from claiming critical network infrastructure, these names CANNOT be
/// mined by users. They are permanently locked and can only be allocated or reassigned by
/// the Kinetic Council via governance proposals.
/// Because they are critical to the network's operation, they are exempt
/// from heartbeat and thermodynamic pruning rules so they never accidentally expire.
pub const INFRASTRUCTURE_NAMES: &[&str] = &[
    "seed", "node", "docs", "dao", "explorer", "status", "api", "blog", "rpc",
];

/// Checks if a given domain name is classified as network infrastructure.
/// Infrastructure names are reserved and cannot be mined by regular users.
pub fn is_infrastructure_name(name: &str) -> bool {
    let norm = crate::types::names::normalize_name(name);
    let apex = crate::types::names::extract_apex_domain(&norm);
    let parts: Vec<&str> = apex.split('.').collect();
    if !parts.is_empty() {
        INFRASTRUCTURE_NAMES.contains(&parts[0])
    } else {
        false
    }
}

/// Determines if a given domain name requires periodic heartbeats to remain active.
/// Infrastructure domains are exempt from heartbeat and pruning rules.
pub fn requires_heartbeat(name: &str) -> bool {
    // Infrastructure names are exempt from heartbeats and pruning
    !is_infrastructure_name(name)
}
