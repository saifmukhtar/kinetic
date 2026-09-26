#![allow(rustdoc::redundant_explicit_links)]
//! # kinetic-network (Layer 7 Trunk)
//!
//! The massive P2P networking trunk of the Kinetic workspace.
//!
//! This crate is the absolute Trunk of Layer 7. It owns everything related to peer-to-peer
//! connections, Kademlia DHT state, and Gossipsub message flooding. It encapsulates the
//! `libp2p::Swarm` within a dedicated Tokio task and exposes a thread-safe `NetworkClient`
//! API so that the Layer 8 executables (`kinetic-daemon`, `kinetic-node`, `kinetic-host`) can
//! safely drive network operations without lock contention.
//!
//! ## Layer 7 Architecture
//! ```text
//!                              [ Layer 8 Executables ]
//!                                         |
//!                                  (mpsc channel)
//!                                         v
//! ............................... [ NetworkClient ] ................................
//! .                                       |                                      .
//! .                               (tokio::select!)                               .
//! .                                       v                                      .
//! .                             [ NetworkEventLoop ]                             .
//! .                            /          |         \                            .
//! .                     (Gossipsub)   (Kademlia)   (AutoNAT)                     .
//! .                          |            |            |                         .
//! .                          v            v            v                         .
//! .                 [ Action/Time ] [ RecordStore ] [ dcutr ]                    .
//! ........................................|.......................................
//!                                         v
//!                               [ kinetic-storage ]
//! ```
//! - **`store`** — The in-memory DHT record store with GC, PoW verification,
//!   and signature validation.
//! - **`behavior`** — The composed libp2p `NetworkBehaviour` combining
//!   Kademlia, gossipsub, mDNS, and request/response.
//! - **`pow`** — Proof-of-Work helpers used to rate-limit DHT writes.
//! - **`error`** — [`KineticStoreError`] variants for store-level failures.

#![deny(missing_docs)]

/// The aggregate network behavior combining Kademlia, Gossipsub, and Proxy layers.
pub mod behavior;
/// The high-level asynchronous client for interacting with the network event loop.
pub mod client;
/// DNS tree structures for name resolution.
pub mod dns_tree;
/// Error types for storage and network operations.
pub mod error;
/// The central background task that drives the libp2p swarm.
pub mod event_loop;
/// Proof-of-Work utilities for Sybil resistance and rate-limiting DHT writes.
pub mod challenge;
/// The in-memory Kademlia record store implementation.
pub mod store;

pub use client::{NetworkClient, NetworkConfig, NetworkMode, ProxyRequest, ProxyResponse};
pub use error::KineticStoreError;
pub use event_loop::NetworkEventLoop;
pub mod peer_registry;
