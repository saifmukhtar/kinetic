//! # kinetic-core
//!
//! The shared kernel for the Kinetic decentralised naming network.
//!
//! This crate contains all the foundational types, traits, and logic that every
//! other crate in the workspace depends on. Nothing in here performs I/O or
//! talks to the network — it is pure, deterministic logic.
//!
//! ## What lives here
//!
//! - **`config`** — [`KineticConfig`](config::KineticConfig) loaded from
//!   `~/.local/share/kinetic/config.toml` and the canonical port constants.
//! - **`types`** — Core domain types: [`DnsZone`](types::DnsZone),
//!   [`DnsRecord`](types::DnsRecord), [`Commitment`](types::Commitment),
//!   [`VdfProof`](types::VdfProof), and helpers for `.kin` name normalisation.
//! - **`error`** — The unified [`KineticError`] hierarchy with typed variants
//!   for publishing, resolution, registration, VDF, and governance failures.
//! - **`traits`** — Abstract interfaces: [`VdfEngine`](traits::VdfEngine) and
//!   [`StorageEngine`](traits::StorageEngine).
//! - **`governance`** — The bicameral council state machine and the
//!   Kinetic Rulebook that governs privileged on-chain actions.
//! - **`consensus_math`** — Deterministic VDF iteration calculations and
//!   grace-period escalation formulas.
//! - **`drand`** — Client for the drand distributed randomness beacon.
//! - **`updater`** — OTA update state machine for daemon self-updates.
//! - **`api_error`** — Axum-compatible [`ApiError`] type for HTTP API handlers.

#![deny(missing_docs)]

/// HTTP API error types compatible with axum and tower response extractors.
#[cfg(not(target_arch = "wasm32"))]
pub mod api_error;
/// Config file loading, default values, and port constants for all Kinetic binaries.
pub mod config;
/// Mathematical helpers for consensus: VDF difficulty scaling and name-length fees.
pub mod consensus_math;
/// Global protocol constants.
pub mod constants;
/// drand beacon client for epoch-bound randomness and Sybil-resistance.
pub mod drand;
/// Unified error types for storage, VDF, KID, and general Kinetic operations.
pub mod error;
/// On-chain governance: council proposals, voting, and parameter updates.
pub mod governance;

/// Idempotency key helpers for deduplicating daemon API requests.
#[cfg(not(target_arch = "wasm32"))]
pub mod request_id;
/// Cross-platform graceful shutdown signal listener.
pub mod shutdown;
/// Core trait definitions: [`StorageEngine`](traits::StorageEngine) and [`VdfEngine`](traits::VdfEngine).
pub mod traits;
/// Shared wire-format types for P2P messages, DNS zones, and domain records.
pub mod types;
#[cfg(not(target_arch = "wasm32"))]
/// Self-updater module for Kinetic node binaries.
pub mod updater;

#[cfg(not(target_arch = "wasm32"))]
pub use api_error::ApiError;

pub use error::{
    KineticError, PublishError, RecordRejectReason, RegistrationError, ResolutionError, Severity,
    VdfRejectReason,
};
