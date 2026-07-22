//! Storage key prefixes used for Kademlia records in the Kinetic network.

/// Prefix for Kademlia records storing reveals.
pub const KRS_REVEAL_PREFIX: &[u8] = b"krs_reveal:";
/// Prefix for Kademlia records storing heartbeats.
pub const KRS_HB_PREFIX: &[u8] = b"krs_hb:";

/// Prefix for Kademlia records storing commitments.
pub const KRS_COMMIT_PREFIX: &[u8] = b"krs_cmt:";
