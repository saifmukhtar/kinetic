//! Protocol-level constants and magic numbers for the Kinetic network.
//!
//! These values define the immutable characteristics of the network (like the TLD
//! or the DID prefix) and are compiled directly into the binary. To fork the network
//! and create an incompatible variant, developers should change these values here
//! before recompiling.

include!(concat!(env!("OUT_DIR"), "/network_constants.rs"));

