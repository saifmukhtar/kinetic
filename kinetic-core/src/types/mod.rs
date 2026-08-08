//! Core wire-format domain models and protocol primitives.
//!
//! Exports all shared data structures used across the Kinetic network protocol:
//!
//! | Module | Key Types | Role |
//! |---|---|---|
//! | `clock` | `KineticTime` | Drand-kyn-to-branded-time conversion |
//! | `dns` | `DnsZone`, `DnsRecord` | DNS zone payload stored in DHT reveal records |
//! | `domain` | `Heartbeat` | Domain heartbeats and DHT key derivation |
//! | `identity` | `AuthorizedKid`, `AuthorizedManifest` | ML-DSA-65 keypair management |
//! | `infrastructure` | `InfraNode` | Bootstrap/infrastructure node metadata |
//! | `names` | validation fns | LDH domain name parsing and normalization |
//! | `vdf` | `VdfProof`, `Commitment` | VDF proof and commitment wire types |

pub mod clock;
pub mod dns;
pub mod name_record;
pub mod identity;
pub mod infrastructure;
#[cfg(not(target_arch = "wasm32"))]
pub mod kid_manager;
pub mod names;
pub mod vdf;

pub use clock::*;
pub use dns::*;
pub use name_record::*;
pub use identity::*;
pub use infrastructure::*;
#[cfg(not(target_arch = "wasm32"))]
pub use kid_manager::*;
pub use names::*;
pub use vdf::*;
