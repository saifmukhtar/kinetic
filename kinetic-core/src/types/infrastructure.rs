//! Category 2 reserved network infrastructure names and heartbeat exemption rules.
//!
//! Infrastructure names (`seed`, `node`, `docs`, `dao`, `explorer`, `status`, `api`, `blog`, `rpc`)
//! are permanently reserved and can only be allocated by the Kinetic Council via governance
//! proposal. Unlike user-owned names, infrastructure names:
//!
//! - **Cannot be mined** (registration will be rejected as [`NamesError::InfrastructureName`](`crate::error::NamesError::InfrastructureName`))
//! - **Are exempt from heartbeat requirements** — they never expire from inactivity
//! - **Are exempt from thermodynamic pruning** — they cannot be stolen by idle-name takeover
//!
//! Contrast with Category 1 reserved names (RFC 2606/6761: `localhost`, `test`, `example`)
//! which are handled by [`NamesError::ReservedName`](`crate::error::NamesError::ReservedName`).

/// Category 2: Kinetic Infrastructure Names.
///
/// These names represent critical network infrastructure (docs, bootstrap nodes, explorer).
/// To prevent squatters from claiming critical network infrastructure, these names CANNOT be
/// mined by users. They are permanently locked and can only be allocated or reassigned by
/// the Kinetic Council via governance proposals.
/// Because they are critical to the network's operation, they are exempt
/// from heartbeat and thermodynamic pruning rules so they never accidentally expire.
pub const INFRASTRUCTURE_NAMES: &[&str] = &[
    "seed", "node", "docs", "dao", "explorer", "status", "api", "blog", "rpc",
];

/// Checks if a given name is classified as a Category 2 network infrastructure name.
///
/// The name is normalized and the apex label is extracted before checking against
/// [`INFRASTRUCTURE_NAMES`]. For example, `"seed.kin"` → apex `"seed.kin"` → label `"seed"` → `true`.
///
/// # Returns
///
/// `true` if the apex label is in the [`INFRASTRUCTURE_NAMES`] list, `false` otherwise.
pub fn is_infrastructure_name(name: &str) -> bool {
    let norm = crate::types::names::normalize_name(name);
    let apex = crate::types::names::extract_apex_name(&norm);
    let parts: Vec<&str> = apex.split('.').collect();
    if !parts.is_empty() {
        INFRASTRUCTURE_NAMES.contains(&parts[0])
    } else {
        false
    }
}

/// Returns whether a given name requires periodic heartbeat records to stay active.
///
/// All user-registered names must publish a [`Heartbeat`](crate::types::domain::Heartbeat)
/// record at regular intervals to prove active ownership. Names that fall idle beyond
/// `STEAL_TARGET_ROUNDS` are eligible for thermodynamic takeover.
///
/// Infrastructure names are permanently exempt from this requirement.
///
/// # Returns
///
/// `true` if the name must publish heartbeats (all non-infrastructure names).
/// `false` if the name is infrastructure-exempt.
pub fn requires_heartbeat(name: &str) -> bool {
    // Infrastructure names are exempt from heartbeats and pruning
    !is_infrastructure_name(name)
}
