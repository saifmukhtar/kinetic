//! # kinetic-local
//!
//! Local file system and OS environment abstractions for the Kinetic Network.
//!
//! ## Layer 6 Architecture: OS & Disk Orchestration
//! This crate operates as the isolated file system boundary. It orchestrates the loading 
//! of TOML configurations, the secure serialization of cryptographic keypairs to disk, 
//! the management of `.kin` identity documents, and OS-level shutdown signals. 
//! It strictly abstracts disk I/O away from the core consensus crates.
//!
//! ## Security & Safety Guarantees
//! - **Keystore Sandboxing:** Enforces strict permission boundaries on identity keystores 
//!   (`secure_fs`) to prevent local privilege escalation attacks (e.g., locking file modes).
//! - **Fail-Closed Configuration:** If `config.toml` is malformed, the node refuses to start 
//!   rather than failing open to dangerous defaults.
//! - **TOCTOU Defenses:** Handles Time-of-Check to Time-of-Use race conditions when 
//!   initializing default data directories.
//!
//! ## Architecture Context
//! ```text
//! [kinetic-daemon / kinetic-node] (Executables)
//!            |
//!            v
//! [kinetic-local::*] (OS Abstraction Layer)
//!      |---------|----------|
//!      v         v          v
//!  [Config] [Keystore] [Shutdown]
//! ```
//!
//! ## Module Map
//!
//! - **[`action`]** — Disk serialization for sovereign network actions.
//! - **[`config`]** — TOML configuration loading and environmental overrides.
//! - **[`identity`]** — Keypair generation and password-protected keystore files.
//! - **[`kid_manager`]** — Orchestration of W3C KID document state transitions.
//! - **[`secure_fs`]** — OS-level file permission hardening.
//! - **[`shutdown`]** — Cross-platform graceful termination signals (SIGINT/SIGTERM).


pub mod action;
pub mod config;
pub mod identity;
#[cfg(not(target_arch = "wasm32"))]
pub mod kid_manager;
pub mod secure_fs;
pub mod shutdown;
