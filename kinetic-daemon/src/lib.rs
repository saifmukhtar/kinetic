#![deny(missing_docs)]
//! The Kinetic daemon library provides the core runtime for a Kinetic node,
//! including the HTTP API, local proxy, PAC server, and background services.

/// The HTTP API server modules.
pub mod api;
/// Certificate Authority generation and caching for TLS proxying.
pub mod ca;
/// Proxy Auto-Configuration (PAC) server and OS integration.
pub mod pac;
/// Local HTTP/HTTPS proxy server for intercepting `.kin` traffic.
pub mod proxy;
/// Background services such as gossip, network loops, and heartbeats.
pub mod services;
