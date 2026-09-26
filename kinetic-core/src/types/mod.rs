//! Core wire-format domain models and protocol primitives.
//!
//! Exports all shared data structures used across the Kinetic network protocol:
//!
//! | Module | Key Types | Role |
//! |---|---|---|
//! | `clock` | `KineticTime` | Drand-kyn-to-branded-time conversion |
//! | `nrs` | `NrsZone`, `NrsEntry` | NRS zone payload stored in DHT reveal records |
//! | `domain` | `Heartbeat` | Domain heartbeats and DHT key derivation |
//! | `identity` | `AuthorizedKid`, `AuthorizedManifest` | ML-DSA-65 keypair management |
//! | `infrastructure` | `InfraNode` | Bootstrap/infrastructure node metadata |
//! | `names` | validation fns | LDH domain name parsing and normalization |
//! | `vdf` | `VdfProof`, `Commitment` | VDF proof and commitment wire types |

pub mod identity;
#[cfg(not(target_arch = "wasm32"))]
pub mod name_record;
pub mod names;
pub mod nrs;
pub mod vdf;

pub use identity::*;
#[cfg(not(target_arch = "wasm32"))]
pub use name_record::*;
pub use names::*;
pub use nrs::*;
pub use vdf::*;
