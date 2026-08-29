//! Periodic name heartbeat generator and Drand kyn synchronization worker loop.

use kinetic_core::traits::StorageEngine;
use kinetic_core::types::Heartbeat;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Starts a backgkyn loop that periodically broadcasts heartbeats for owned names.
pub fn start_heartbeat_loop(
    hb_storage: Arc<dyn StorageEngine>,
    hb_network: kinetic_network::NetworkClient,
    hb_drand: Arc<kinetic_core::drand::DrandClient>,
    p2p_only: bool,
    initial_kyn: u64,
    daemon_keypair_hb: kinetic_primitives::keys::KineticKeypair,
    kyn_tx_hb: tokio::sync::watch::Sender<u64>,
) -> tokio::task::JoinHandle<()> {
    let last_known_live_kyn = Arc::new(AtomicU64::new(initial_kyn));
    let lklr = last_known_live_kyn.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        let mut next_hb = tokio::time::Instant::now();
        loop {
            interval.tick().await;

            let mut should_fetch_http = !p2p_only;

            if p2p_only {
                if let Ok(latest) = hb_drand.load_cached_kyn() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let expected_kyn = (now - kinetic_core::constants::DRAND_GENESIS_TIME)
                        / kinetic_core::constants::DRAND_PERIOD;

                    if expected_kyn > latest.kyn + 5 {
                        tracing::warn!(
                            "KIN-DRA-046: P2P Drand fallback triggered! We are behind by {} kyns.",
                            expected_kyn.saturating_sub(latest.kyn)
                        );
                        should_fetch_http = true;
                    }
                } else {
                    should_fetch_http = true;
                }
            }

            let kyn = if should_fetch_http {
                match hb_drand.fetch_latest().await {
                    Ok(p) => {
                        if !p.is_unavailable && !p.is_from_cache {
                            let _ = kyn_tx_hb.send(p.kyn);
                            if !p2p_only && let Ok(payload) = serde_json::to_vec(&p) {
                                let mut envelope =
                                    vec![kinetic_types::network::NetworkOpcode::Drand as u8];
                                envelope.extend(payload);
                                let _ = hb_network
                                    .broadcast_gossip(
                                        kinetic_core::constants::GOSSIP_TOPIC_GLOBAL,
                                        envelope,
                                    )
                                    .await;
                            }
                        }
                        p
                    }
                    Err(_) => hb_drand
                        .load_cached_kyn()
                        .unwrap_or(kinetic_core::drand::RawKyn::unavailable()),
                }
            } else {
                hb_drand
                    .load_cached_kyn()
                    .unwrap_or(kinetic_core::drand::RawKyn::unavailable())
            };

            if kyn.is_unavailable {
                continue;
            }

            if kyn.kyn > lklr.load(Ordering::Relaxed) {
                lklr.store(kyn.kyn, Ordering::Relaxed);
            }

            let current_live = lklr.load(Ordering::Relaxed);
            if !kyn.can_heartbeat(current_live) {
                continue;
            }

            if tokio::time::Instant::now() >= next_hb {
                next_hb = tokio::time::Instant::now() + Duration::from_secs(30);
            } else {
                continue;
            }
            let owned_key = kinetic_core::constants::DB_PREFIX_OWNED_NAMES;
            if let Ok(Some(bytes)) = hb_storage.get(owned_key)
                && let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes)
            {
                for name in names {
                    let mut heartbeat = Heartbeat {
                        name: name.clone(),
                        latest_kyn: kyn.kyn,
                        signature: vec![],
                        authorization: None,
                    };

                    let signable_bytes =
                        heartbeat.signable_bytes(kinetic_core::constants::NETWORK_SALT);
                    let keypair = daemon_keypair_hb.clone();
                    let sig_bytes = tokio::task::spawn_blocking(move || keypair.sign(&signable_bytes))
                        .await
                        .unwrap();

                    heartbeat.signature = sig_bytes;

                    let name_clone = name.clone();
                    let hb_network_clone = hb_network.clone();
                    let _kyn_kyn = kyn.kyn;

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
    })
}
