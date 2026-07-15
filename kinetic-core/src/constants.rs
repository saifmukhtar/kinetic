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

/// The unique Network ID used to isolate P2P protocols (Kademlia, Gossipsub) and local mDNS discovery.
/// Must be changed when creating an isolated fork.
pub const NETWORK_ID: &str = "kinetic";

/// Unix timestamp of the Drand chain's genesis.
pub const DRAND_GENESIS_TIME: u64 = 1692803367;

/// Duration in seconds of each Drand round.
pub const DRAND_PERIOD: u64 = 3;

/// The League of Entropy public key for the Quicknet chain (or custom beacon).
pub const DRAND_PUBLIC_KEY: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";

/// The set of Drand HTTP endpoints tried in order.
pub const DRAND_HTTP_ENDPOINTS: &[&str] = &[
    "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest",
    "https://drand.cloudflare.com/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest",
    "https://api2.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest",
    "https://api3.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest",
];
