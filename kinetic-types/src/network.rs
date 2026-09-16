//! Core network taxonomies and opcodes for peer-to-peer communication.
//!
//! Defines the strict binary formats used by the network layer to efficiently
//! multiplex distinct message channels (like Action and KineticTime) over a 
//! single global P2P publication topic.

/// 1-byte opcode prepended to all P2P payloads on the global publication topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetworkOpcode {
    /// Action broadcast authorized by the Sovereign key.
    Action = 0x01,
    /// Clock synchronization pulse from the KineticTime consensus beacon.
    Drand = 0x02,
    /// Anonymous network health statistics.
    Telemetry = 0x03,
}

impl NetworkOpcode {
    /// Safely parses a single byte into a `NetworkOpcode`, if recognized.
    ///
    /// # Examples
    /// ```rust
    /// use kinetic_types::network::NetworkOpcode;
    ///
    /// assert_eq!(NetworkOpcode::from_u8(0x01), Some(NetworkOpcode::Action));
    /// assert_eq!(NetworkOpcode::from_u8(0xFF), None);
    /// ```
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::Action),
            0x02 => Some(Self::Drand),
            0x03 => Some(Self::Telemetry),
            _ => None,
        }
    }
}

use serde::{Deserialize, Serialize};

/// Identifies the specific Kinetic binary running on the network.
///
/// Used in telemetry to distinguish between local user clients (`Daemon`), 
/// public infrastructure routers (`Node`), and headless seeders (`Host`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    Daemon,
    Node,
    Host,
}

/// Identifies the node's architectural participation level.
///
/// Used in telemetry to map the ratio of `FullNode` vs `LightNode` participation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMode {
    FullNode,
    LightNode,
}

/// A highly restricted enumeration of Operating Systems.
///
/// Used in telemetry instead of raw `std::env::consts::OS` strings to strictly 
/// prevent hardware/software fingerprinting and protect user anonymity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OsType {
    Linux,
    Windows,
    Macos,
    Other,
}

/// Indicates whether the node can accept incoming TCP connections.
///
/// Used in telemetry to gauge network health and NAT traversal success rates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Reachability {
    Public,
    BehindNAT,
}

/// Opt-in, anonymous payload broadcast to map global network health without tracking users.
///
/// This structure aggregates network performance metrics and node statuses to help 
/// developers diagnose P2P network health, without exposing any personally identifiable 
/// information or deterministic hardware fingerprints.
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
    /// The latest KineticTime pulse the node has verified, used to detect sync failures.
    pub latest_kyn: u64,
    /// Total Megabytes sent since boot.
    pub mb_sent: u32,
    /// Total Megabytes received since boot.
    pub mb_received: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_network_opcode_parsing() {
        // Valid OpCodes
        assert_eq!(NetworkOpcode::from_u8(0x01), Some(NetworkOpcode::Action));
        assert_eq!(NetworkOpcode::from_u8(0x02), Some(NetworkOpcode::Drand));
        assert_eq!(NetworkOpcode::from_u8(0x03), Some(NetworkOpcode::Telemetry));

        // Invalid OpCodes
        assert_eq!(NetworkOpcode::from_u8(0x00), None);
        assert_eq!(NetworkOpcode::from_u8(0x04), None);
        assert_eq!(NetworkOpcode::from_u8(0xFF), None);
    }

    #[test]
    fn test_telemetry_heartbeat_serialization() {
        let heartbeat = TelemetryHeartbeat {
            session_id: "uuid-1234".to_string(),
            version: "0.2.0".to_string(),
            os: OsType::Linux,
            connected_peers: 42,
            uptime_seconds: 3600,
            node_type: NodeType::Daemon,
            network_mode: NetworkMode::LightNode,
            reachability: Reachability::Public,
            latest_kyn: 123456,
            mb_sent: 15,
            mb_received: 30,
        };

        // Ensure it serializes successfully
        let json_str = serde_json::to_string(&heartbeat).expect("Failed to serialize heartbeat");
        assert!(json_str.contains("uuid-1234"));
        assert!(json_str.contains("Linux"));
        assert!(json_str.contains("LightNode"));
        assert!(json_str.contains("Public"));

        // Ensure it deserializes back perfectly
        let deserialized: TelemetryHeartbeat =
            serde_json::from_str(&json_str).expect("Failed to deserialize heartbeat");

        assert_eq!(deserialized.session_id, "uuid-1234");
        assert_eq!(deserialized.connected_peers, 42);
        assert_eq!(deserialized.latest_kyn, 123456);
    }
}
