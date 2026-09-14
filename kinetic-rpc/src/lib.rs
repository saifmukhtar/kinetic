//! # kinetic-rpc
//!
//! The HTTP serialization boundary and request-tracing framework for the Kinetic Network.
//!
//! ## Layer 4 Architecture: Network Boundary Adapter
//! This crate operates strictly as an infrastructural adapter. It translates internal
//! domain errors (`kinetic-core::error`) into standardized HTTP JSON responses adhering 
//! to RFC 7807 (Problem Details for HTTP APIs). It explicitly ignores Kinetic consensus 
//! rules, identity validation, and cryptography, serving solely as a translation layer 
//! between the daemon's internal state and external web clients.
//!
//! ## Core Functions
//! - **Status Code Mapping:** Prevents HTTP status code logic (e.g. `404 Not Found` vs 
//!   `502 Bad Gateway`) from leaking into core consensus crates.
//! - **Asynchronous Tracing:** Provides Tokio task-local `request_id` correlation for 
//!   telemetry spanning complex asynchronous execution trees.
//!
//! ## Architecture Context
//! ```text
//! [kinetic-core::error::*] (Internal Domain Errors)
//!            |
//!            v
//! [kinetic-rpc::api_error::ApiError] (RFC 7807 Mapping)
//!            |
//!            v
//! [kinetic-daemon HTTP Handlers] (External JSON Responses)
//! ```

#![deny(missing_docs)]

pub mod api_error;
pub mod request_id;

pub use api_error::ApiError;
