
use kinetic_core::types::Heartbeat;
use kinetic_core::traits::StorageEngine;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use ed25519_dalek::Signer;

pub fn start_heartbeat_loop(
    hb_storage: Arc<kinetic_storage::SledStorage>,
    hb_network: kinetic_network::NetworkClient,
    hb_drand: Arc<kinetic_core::drand::DrandClient>,
    p2p_only: bool,
    initial_drand_pulse: u64,
    daemon_keypair_hb: ed25519_dalek::SigningKey,
    drand_pulse_tx_hb: tokio::sync::watch::Sender<u64>,
) -> tokio::task::JoinHandle<()> {
    let last_known_live_round = Arc::new(AtomicU64::new(initial_drand_pulse));
    let lklr = last_known_live_round.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        let mut next_hb = tokio::time::Instant::now();
        loop {
            interval.tick().await;

            let mut should_fetch_http = !p2p_only;

            if p2p_only {
                if let Ok(latest) = hb_drand.load_cached_pulse() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let expected_round = now.saturating_sub(kinetic_core::drand::QUICKNET_GENESIS_TIME) / 3;

                    if expected_round > latest.round + 5 {
                        tracing::warn!(
                            "P2P Drand fallback triggered! We are behind by {} rounds.",
                            expected_round.saturating_sub(latest.round)
                        );
                        should_fetch_http = true;
                    }
                } else {
                    should_fetch_http = true;
                }
            }

            let pulse = if should_fetch_http {
                match hb_drand.fetch_latest().await {
                    Ok(p) => {
                        if !p.is_unavailable && !p.is_from_cache {
                            let _ = drand_pulse_tx_hb.send(p.round);
                            if !p2p_only {
                                if let Ok(payload) = serde_json::to_vec(&p) {
                                    let _ = hb_network
                                        .broadcast_gossip("drand_pulse_quicknet", payload)
                                        .await;
                                }
                            }
                        }
                        p
                    }
                    Err(_) => hb_drand
                        .load_cached_pulse()
                        .unwrap_or(kinetic_core::drand::DrandPulse::unavailable()),
                }
            } else {
                hb_drand
                    .load_cached_pulse()
                    .unwrap_or(kinetic_core::drand::DrandPulse::unavailable())
            };

            if pulse.is_unavailable {
                continue;
            }

            if pulse.round > lklr.load(Ordering::Relaxed) {
                lklr.store(pulse.round, Ordering::Relaxed);
            }

            let current_live = lklr.load(Ordering::Relaxed);
            if !pulse.is_usable_for_heartbeat(current_live) {
                continue;
            }

            if tokio::time::Instant::now() >= next_hb {
                next_hb = tokio::time::Instant::now() + Duration::from_secs(30);
            } else {
                continue;
            }
            let owned_key = b"kinetic_owned_names";
            if let Ok(Some(bytes)) = hb_storage.get(owned_key) {
                if let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes) {
                    for name in names {
                        let mut heartbeat = Heartbeat {
                            name: name.clone(),
                            latest_drand_pulse: pulse.round,
                            signature: vec![],
                        };

                        let sig = daemon_keypair_hb.sign(&heartbeat.signable_bytes());
                        heartbeat.signature = sig.to_vec();

                        let name_clone = name.clone();
                        let hb_network_clone = hb_network.clone();
                        let pulse_round = pulse.round;

                        tokio::spawn(async move {
                            if let Ok(payload) = serde_json::to_vec(&heartbeat) {
                                let _ = hb_network_clone
                                    .publish_heartbeat(&name_clone, payload)
                                    .await;
                            }
                        });
                    }
                }
            }
        }
    })
}
