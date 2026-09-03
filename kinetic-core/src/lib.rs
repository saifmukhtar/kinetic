#![allow(rustdoc::redundant_explicit_links)]
//! # kinetic-core
//!
//! The foundational shared kernel for the Kinetic decentralized naming network.
//!
//! `kinetic-core` contains the core models, protocol constants, cryptographic
//! state machines, error hierarchies, and common I/O utilities used across all Kinetic
//! binaries and sub-crates.
//!
//! ## Architecture & Module Map
//!
//! - **[`config`]** — Daemon configuration structures ([`KineticConfig`](config::KineticConfig)) and network port defaults.
//! - **[`types`]** — Shared wire-format types ([`NrsZone`](types::NrsZone), [`NrsRecord`](types::NrsRecord), [`Commitment`](types::Commitment), [`VdfProof`](types::VdfProof)) and name normalization rules.
//! - **[`error`]** — Unified error logbook ([`KineticError`](error::KineticError)), domain errors ([`ResolutionError`](error::ResolutionError), [`PublishError`](error::PublishError), [`RegistrationError`](error::RegistrationError)), and stable error codes.
//! - **[`traits`]** — Core abstraction traits ([`StorageEngine`](traits::StorageEngine) and [`VdfEngine`](traits::VdfEngine)).
//! - **[`governance`]** — Sovereign state machine and parameter rulebooks governing privileged protocol actions.
//! - **[`consensus_math`]** — Deterministic math routines for VDF difficulty scaling, name-length pricing, and grace period calculations.
//! - **[`drand`]** — Client interface for the drand distributed randomness beacon used in time-bound operations.
//! - **[`net`]** — Network security primitives, IP classification, and SSRF prevention guards.
//! - **[`shutdown`]** — Cross-platform graceful shutdown listeners.

//! - **[`api_error`]** *(Non-WASM)* — HTTP status code mapping and Axum-compatible API error responses ([`ApiError`](api_error::ApiError)).
//! - **[`request_id`]** *(Non-WASM)* — Idempotency key generators for daemon API requests.

#![deny(missing_docs)]

/// Config file loading, default values, and port constants for all Kinetic binaries.
pub mod config;
/// Mathematical helpers for consensus: VDF difficulty scaling and name-length fees.
pub mod consensus_math;
/// Global protocol constants.
pub mod constants;
/// drand beacon client for epoch-bound randomness and Sybil-resistance.
pub mod drand;
/// Unified error taxonomy: [`KineticError`](error::KineticError), [`ResolutionError`](error::ResolutionError), [`PublishError`](error::PublishError), and [`RegistrationError`](error::RegistrationError).
pub mod error;
/// Network security utilities for SSRF prevention.
pub mod net;
/// Core trait definitions: [`StorageEngine`](traits::StorageEngine) and [`VdfEngine`](traits::VdfEngine).
pub mod traits;
/// Shared wire-format types for P2P messages, DNS zones, and name records.
pub mod types;

/// Primary protocol error taxonomy re-exported at crate root:
/// - [`KineticError`]: Top-level unified error enum.
/// - [`PublishError`]: Record publication failures (`KIN-PUB-*`).
/// - [`RegistrationError`]: Name registration failures (`KIN-REG-*`).
/// - [`ResolutionError`]: DHT name resolution failures (`KIN-QRY-*`).
/// - [`RecordRejectReason`]: Storage engine rejection codes.
/// - [`VdfRejectReason`]: VDF proof validation rejection reasons.
/// - [`Severity`]: Logging & monitoring alert severity classifier (`Info`, `Warning`, `Error`, `Critical`).
pub use error::{
    KineticError, PublishError, RecordRejectReason, RegistrationError, ResolutionError, Severity,
    VdfRejectReason,
};
/// Protocol governance: sovereign actions, root keys, and parameter updates.
pub mod governance;
