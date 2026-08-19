//! Category 2 reserved network protocol names and heartbeat exemption rules.
//!
//! Protocol names (`seed`, `node`, `docs`, `status`, `api`, `blog`, `rpc`, `foundation`, `metrics`)
//! are permanently reserved and can only be allocated by the Kinetic Council via governance
//! proposal. Unlike user-owned names, protocol names:
//!
//! - **Cannot be mined** (registration will be rejected as [`NamesError::ProtocolName`](`crate::error::NamesError::ProtocolName`))
//! - **Are exempt from heartbeat requirements** — they never expire from inactivity
//! - **Are exempt from thermodynamic pruning** — they cannot be stolen by idle-name takeover
//!
//! Contrast with Category 1 reserved names (RFC 2606/6761: `localhost`, `test`, `example`)
//! which are handled by [`NamesError::ReservedName`](`crate::error::NamesError::ReservedName`).

/// Category 2: Kinetic Protocol Names.
///
/// These names represent critical network protocol functionality (docs, bootstrap nodes, explorer).
/// To prevent squatters from claiming critical network protocol names, these names CANNOT be
/// mined by users. They are permanently locked and can only be allocated or reassigned by
/// the Kinetic Council via governance proposals.
/// Because they are critical to the network's operation, they are exempt
/// from heartbeat and thermodynamic pruning rules so they never accidentally expire.
pub const PROTOCOL_NAMES: &[&str] = &[
    "seed",
    "node",
    "docs",
    "status",
    "api",
    "blog",
    "rpc",
    "foundation",
    "metrics",
];

/// Checks if a given name is classified as a Category 2 network protocol name.
///
/// The name is normalized and the apex label is extracted before checking against
/// [`PROTOCOL_NAMES`]. For example, `"seed.kin"` → apex `"seed.kin"` → label `"seed"` → `true`.
///
/// # Returns
///
/// `true` if the apex label is in the [`PROTOCOL_NAMES`] list, `false` otherwise.
pub fn is_protocol_name(name: &str) -> bool {
    let norm = crate::types::names::normalize_name(name);
    let apex = crate::types::names::extract_apex_name(&norm);
    let parts: Vec<&str> = apex.split('.').collect();
    if !parts.is_empty() {
        PROTOCOL_NAMES.contains(&parts[0])
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
/// Protocol names are permanently exempt from this requirement.
///
/// # Returns
///
/// `true` if the name must publish heartbeats (all non-protocol names).
/// `false` if the name is protocol-exempt.
pub fn requires_heartbeat(name: &str) -> bool {
    // Protocol names are exempt from heartbeats and pruning
    !is_protocol_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_names_exempt_from_heartbeats() {
        assert!(!requires_heartbeat("seed.kin"));
        assert!(!requires_heartbeat("docs.kin"));
        assert!(!requires_heartbeat("api.kin"));
        assert!(!requires_heartbeat("status.kin"));
    }

    #[test]
    fn test_normal_names_require_heartbeats() {
        assert!(requires_heartbeat("satoshi.kin"));
        assert!(requires_heartbeat("a.kin")); // Prime names require heartbeats
        assert!(requires_heartbeat("blog.satoshi.kin"));
        assert!(requires_heartbeat("something.kin"));
    }
}
