//! Canonical data types, schemas, and cryptographic serialization for the Kinetic network.
//!
//! `kinetic-types` serves as the Layer 3 data schema hub for the entire
//! Kinetic workspace. It defines the core data contracts, wire serialization formats,
//! and cryptographic structures needed by nodes, clients, browser extensions, wallets,
//! and offline toolchains without pulling in heavy consensus or networking engines.
//!
//! ## Subsystem Architecture
//!
//! - [`action`]: Network actions, signed network proposal containers ([`SignedActionMessage`](action::SignedActionMessage)), and strict binary payload parsers.
//! - [`cdn`]: Request/Response taxonomies for the distributed P2P CDN caching layer.
//! - [`clock`]: Domain-specific time hierarchy based on mathematical consensus beacons (Kyns, Facets, Prisms, Matrices, Lattices, Apexes).
//! - [`error`]: Common error taxonomy metadata and deterministic severity classifications ([`Severity`](error::Severity)).
//! - [`identity`]: Kinetic Identity Document ([`AuthorizedKid`](identity::AuthorizedKid)) and capability manifest attachments ([`AuthorizedManifest`](identity::AuthorizedManifest)) with Cross-Network Replay Protection.
//! - [`name_record`]: Registration containers ([`NameRecord`](name_record::NameRecord)), active routing liveness proofs ([`Heartbeat`](name_record::Heartbeat)), and DHT key derivation.
//! - [`network`]: Taxonomies and payload opcodes for P2P publication multiplexing.
//! - [`nrs`]: Name Resolution System (NRS) zone definitions, routing variants, and decentralized host routing bindings.
//! - [`proxy`]: High-performance zero-copy IPC proxy payloads for local `kinetic-daemon` browser integration.
//! - [`vdf`]: Proof of Patience commitments, mathematical evaluation proofs ([`VdfProof`](vdf::VdfProof)), and deterministic registration submissions ([`Reveal`](vdf::Reveal)).

pub mod action;
pub mod cdn;
pub mod error;
pub mod identity;
pub mod name_record;
pub mod network;
pub mod nrs;

pub mod proxy;
pub mod pubkey_serde;
pub mod sig_serde;
pub mod vdf;
