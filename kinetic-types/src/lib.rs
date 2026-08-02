//! Canonical data types, schemas, and cryptographic serialization for the Kinetic network.
//!
//! `kinetic-types` serves as the zero-dependency, lightweight type hub for the entire
//! Kinetic workspace. It defines the core data contracts, wire serialization formats,
//! and cryptographic structures needed by nodes, clients, browser extensions, wallets,
//! and offline toolchains without pulling in heavy consensus or networking engines.
//!
//! ## Subsystem Architecture
//!
//! - [`clock`]: Branded time hierarchy ([`KineticTime`](clock::KineticTime)) based on Drand rounds (Pulses, Cycles, Epochs, Orbits).
//! - [`dns`]: DNS zone definitions, record variants (`A`, `AAAA`, `CNAME`, `TXT`, `PeerId`, `KID`, `IPFS`), and P2P routing records.
//! - [`name_record`]: Name records ([`NameRecord`](name_record::NameRecord)), heartbeat liveness proofs ([`Heartbeat`](name_record::Heartbeat)), and signature verification.
//! - [`error`]: Common error taxonomy metadata and severity classifications ([`Severity`](error::Severity)).
//! - [`governance`]: Governance actions, signed proposal containers ([`SignedGovernanceMessage`](governance::SignedGovernanceMessage)), binary opcodes, and parser error types.
//! - [`identity`]: Key Identifier ([`AuthorizedKid`](identity::AuthorizedKid)) and capability manifest attachments ([`AuthorizedManifest`](identity::AuthorizedManifest)) with replay protection.
//! - [`proxy`]: High-performance IPC proxy requests and responses for browser and desktop integration.
//! - [`vdf`]: Proof-of-work commitment ([`Commitment`](vdf::Commitment)), evaluation proofs ([`VdfProof`](vdf::VdfProof)), and reveal submissions ([`Reveal`](vdf::Reveal)) with ML-DSA-65 signature verification.

pub mod clock;
pub mod dns;
pub mod name_record;
pub mod error;
pub mod governance;
pub mod identity;
pub mod proxy;
pub mod vdf;
