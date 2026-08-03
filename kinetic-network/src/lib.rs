#![allow(rustdoc::redundant_explicit_links)]
//! # kinetic-network
//!
//! The libp2p networking layer for the Kinetic decentralised naming network.
//!
//! This crate owns everything related to peer-to-peer communication. It wraps
//! libp2p into a clean, channel-based API so that the rest of the workspace
//! (daemon, node, host) can interact with the network without needing to know
//! anything about swarm internals.
//!
//! ## Architecture
//!
//! The crate is built around a single long-running task — [`NetworkEventLoop`]
//! — that drives the libp2p swarm. All callers interact with it exclusively
//! through a [`NetworkClient`] handle, which communicates via a bounded
//! `mpsc` channel. This design keeps the swarm single-threaded and avoids any
//! locking on the hot path.
//!
//! ## What lives here
//!
//! - **`client`** — The [`NetworkClient`] handle and the [`NetworkConfig`]
//!   used to initialise the swarm. Also exposes [`NetworkMode`] (FullNode /
//!   LightNode) and the [`ProxyRequest`] / [`ProxyResponse`] types.
//! - **`event_loop`** — The [`NetworkEventLoop`] task and its swarm builder,
//!   event handlers, and utility functions.
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
pub mod pow;
/// The in-memory Kademlia record store implementation.
pub mod store;

pub use client::{NetworkClient, NetworkConfig, NetworkMode, ProxyRequest, ProxyResponse};
pub use error::KineticStoreError;
pub use event_loop::NetworkEventLoop;
