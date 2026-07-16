//! Protocol-level constants and magic numbers for the Kinetic network.
//!
//! These values define the immutable characteristics of the network (like the TLD
//! or the DID prefix) and are compiled directly into the binary. To fork the network
//! and create an incompatible variant, developers should change these values here
//! before recompiling.

// ============================================================================
// 1. DYNAMIC NETWORK CONFIGURATION
// Generated automatically from network.json by build.rs.
// Includes: TLD, NETWORK_ID, GOVERNANCE_MODEL, BOOTSTRAP_NODES, etc.
// ============================================================================
include!(concat!(env!("OUT_DIR"), "/network_constants.rs"));

// ============================================================================
// 2. GOVERNANCE CONSENSUS TIMINGS & LIMITS
// Used by: `kinetic-core/src/governance/logic.rs` and engines
// ============================================================================

/// The minimum number of active council members required to ratify actions.
pub const MIN_ACTIVE_COUNCIL: usize = 7;

/// The hard limit on the total size of the active council.
pub const MAX_COUNCIL_SIZE: usize = 21;

/// The maximum time (in seconds) a governance proposal is valid before it expires.
pub const MAX_AGE_SECONDS: u64 = 14 * 24 * 60 * 60;

/// The mandatory timelock (in seconds) before an executed action (like Emergency Reset) becomes permanent.
pub const TIMELOCK_SECONDS: u64 = 30 * 24 * 60 * 60;

/// The rolling window (in seconds) during which a council member must have signed something to be considered "active".
pub const ACTIVE_WINDOW_SECONDS: u64 = 30 * 24 * 60 * 60;

/// The time (in seconds) after genesis at which the Founder phase automatically begins gracefully degrading to Council mode.
pub const AUTO_LOCK_SECONDS: u64 = 365 * 24 * 60 * 60;

/// The specific timelock (in seconds) for Over-The-Air (OTA) binary updates.
pub const OTA_TIMELOCK_SECONDS: u64 = 48 * 60 * 60;

// ============================================================================
// 3. GOVERNANCE CRYPTOGRAPHY
// Used by: `kinetic-core/src/governance/logic.rs` and engines
// ============================================================================

// --- PRODUCTION KEYS ---
#[cfg(not(test))]
mod keys {
    /// The offline, air-gapped Ed25519 root of trust.
    pub const ROOT_PUBLIC_KEY_HEX: &str = "REPLACE_ME_OFFLINE_GENERATED_ED25519_ROOT";
    /// The offline, air-gapped Ed25519 guard key (optional fallback).
    pub const GUARD_PUBLIC_KEY_HEX: &str = "REPLACE_ME_OFFLINE_GENERATED_ED25519_GUARD";
}

pub use keys::*;

// --- TEST KEYS ---
#[cfg(test)]
mod keys {
    /// The offline, air-gapped Ed25519 root of trust (test key).
    pub const ROOT_PUBLIC_KEY_HEX: &str =
        "be907b4bac84fee5ce8811db2defc9bf0b2a2a2bbc3d54d8a2257ecd70441962";
    /// The offline, air-gapped Ed25519 guard key (test key).
    pub const GUARD_PUBLIC_KEY_HEX: &str =
        "207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6";
}
