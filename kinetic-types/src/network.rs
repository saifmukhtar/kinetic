//! Core network taxonomies and opcodes for peer-to-peer communication.
//!
//! Defines the strict binary formats used by the network layer to efficiently
//! multiplex distinct message channels (like Governance and Drand) over a single
//! global Gossipsub topic.

/// 1-byte opcode prepended to all Gossipsub payloads on the global topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetworkOpcode {
    /// Action broadcast by the root authority.
    Governance = 0x01,
    /// Clock synchronization pulse from the Drand Quicknet.
    Drand = 0x02,
    /// Anonymous network health statistics.
    Telemetry = 0x03,
}

impl NetworkOpcode {
    /// Safely parses a single byte into a `NetworkOpcode`, if recognized.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::Governance),
            0x02 => Some(Self::Drand),
            0x03 => Some(Self::Telemetry),
            _ => None,
        }
    }
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    Daemon,
    Node,
    Host,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMode {
    FullNode,
    LightNode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OsType {
    Linux,
    Windows,
    Macos,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Reachability {
    Public,
    BehindNAT,
}

/// Opt-in, anonymous payload broadcast to map global network health without tracking users.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryHeartbeat {
    /// A temporary, random ID generated in RAM at boot to prevent node profiling.
    pub session_id: String,
    /// Software version (e.g., "0.2.0").
    pub version: String,
    /// Operating system (strict enum to prevent fingerprinting).
    pub os: OsType,
    /// Number of connected peers.
    pub connected_peers: u32,
    /// Seconds since process start.
    pub uptime_seconds: u64,

    // --- Rich Metrics ---
    /// The binary running this node.
    pub node_type: NodeType,
    /// Mode the node is running in ("FullNode" or "LightNode").
    pub network_mode: NetworkMode,
    /// Whether the node is publicly reachable.
    pub reachability: Reachability,
    /// The latest Drand pulse the node has verified, used to detect sync failures.
    pub latest_kyn: u64,
    /// Total Megabytes sent since boot.
    pub mb_sent: u32,
    /// Total Megabytes received since boot.
    pub mb_received: u32,
}
