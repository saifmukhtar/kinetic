//! Protocol-level constants and magic numbers for the Kinetic network.
//!
//! These values define the immutable characteristics of the network (like the TLD
//! or the DID prefix) and are compiled directly into the binary. To fork the network
//! and create an incompatible variant, developers should change these values here
//! before recompiling.

/// The default Top Level Domain (TLD) for the Kinetic network.
pub const TLD: &str = "kin";

/// The suffix format for Kinetic names, including the preceding dot.
pub const TLD_SUFFIX: &str = ".kin";

/// The prefix used for Decentralized Identifiers (DIDs) on the Kinetic network.
pub const DID_PREFIX: &str = "did:kin:";

/// The default DNS seed domain for discovering P2P bootstrap nodes.
pub const SEED_DOMAIN: &str = "seed.saifmukhtar.dev";

/// The default domain for discovering Drand randomness beacon endpoints via DNS TXT records.
pub const DRAND_DOMAIN: &str = "drand.saifmukhtar.dev";
