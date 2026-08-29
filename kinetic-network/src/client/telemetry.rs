//! Periodic network telemetry heartbeat broadcast service.

use kinetic_core::config::KineticConfig;
use kinetic_types::network::{
    NetworkMode, NetworkOpcode, NodeType, OsType, Reachability, TelemetryHeartbeat,
};
use std::env;
use std::sync::Arc;
use std::time::Duration;

/// Starts the background telemetry loop that occasionally broadcasts
/// opt-in, anonymous network metrics over `GOSSIP_TOPIC_GLOBAL`.
pub fn start_telemetry_service(
    network_client: crate::client::core::NetworkClient,
    drand_client: Arc<kinetic_core::drand::DrandClient>,
    config: KineticConfig,
    node_type: NodeType,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Generate a random temporary ID for this boot session in RAM.
        let mut session_id = uuid::Uuid::new_v4().to_string();
        let mut session_generated_at_kyn =
            drand_client.load_cached_kyn().map(|k| k.kyn).unwrap_or(0);
        let process_start_time = tokio::time::Instant::now();

        // 10 minute interval
        let mut interval = tokio::time::interval(Duration::from_secs(600));

        loop {
            interval.tick().await;

            let latest_kyn = drand_client.load_cached_kyn().map(|k| k.kyn).unwrap_or(0);

            // 24-Hour TTL Auto-Expire
            // If the process has seen 28,800 Kyns (24 hours) since the last rotation,
            // we discard the Session ID and generate a new one to guarantee absolute privacy
            // and prevent long-term node tracking.
            if latest_kyn.saturating_sub(session_generated_at_kyn) >= 28800 {
                session_id = uuid::Uuid::new_v4().to_string();
                session_generated_at_kyn = latest_kyn;
                tracing::debug!("Telemetry session ID automatically rotated for privacy.");
            }

            if !config.network.enable_anonymous_telemetry {
                continue;
            }

            let os = match env::consts::OS {
                "linux" => OsType::Linux,
                "windows" => OsType::Windows,
                "macos" => OsType::Macos,
                _ => OsType::Other,
            };

            let network_mode = match config.daemon.network_mode.as_str() {
                "LightNode" => NetworkMode::LightNode,
                _ => NetworkMode::FullNode,
            };

            let metrics = network_client
                .get_network_status()
                .await
                .unwrap_or_default();

            let reachability =
                if let Some(status_str) = metrics.get("nat_status").and_then(|v| v.as_str()) {
                    if status_str.contains("Private") {
                        Reachability::BehindNAT
                    } else {
                        Reachability::Public
                    }
                } else {
                    Reachability::Public
                };

            let hb = TelemetryHeartbeat {
                session_id: session_id.clone(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                os,
                connected_peers: metrics
                    .get("connected_peers")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                uptime_seconds: process_start_time.elapsed().as_secs(),
                node_type: node_type.clone(),
                network_mode,
                reachability,
                latest_kyn,
                mb_sent: metrics
                    .get("bytes_sent")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32
                    / 1024
                    / 1024,
                mb_received: metrics
                    .get("bytes_received")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32
                    / 1024
                    / 1024,
            };

            if let Ok(json) = serde_json::to_vec(&hb) {
                tracing::debug!("Broadcasting telemetry: {:?}", hb);
                let mut payload = Vec::with_capacity(1 + json.len());
                payload.push(NetworkOpcode::Telemetry as u8);
                payload.extend_from_slice(&json);

                if let Err(e) = network_client
                    .broadcast_gossip(kinetic_core::constants::GOSSIP_TOPIC_GLOBAL, payload)
                    .await
                {
                    tracing::warn!("KIN-TEL-002: Failed to broadcast telemetry: {}", e);
                }
            }
        }
    })
}
