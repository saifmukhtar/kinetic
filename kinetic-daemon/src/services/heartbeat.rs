//! Periodic name heartbeat generator and KYN Time Oracle synchronization worker loop.
//!
//! ## Layer 8 Architecture: The Liveness Engine
//! Domains on the Kinetic network require periodic "heartbeats" to prove liveness and
//! remain discoverable. This background worker constantly queries the local Storage engine
//! for locally owned `.kin` names, calculates the current cryptographic KYN epoch, and
//! floods `Heartbeat` packets over the Gossipsub mesh.

use kinetic_core::traits::KynProvider;
use kinetic_core::traits::StorageEngine;
use kinetic_core::types::Heartbeat;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Initiates the domain Liveness Heartbeat broadcaster.
///
/// > [!NOTE]
/// > Because the Kinetic DHT does not store static ledgers, namespaces will naturally
/// > expire if the owner goes offline. The owner must periodically "pulse" the network
/// > to prove they are still actively hosting the domain.
///
/// This asynchronous loop wakes up every 10 seconds. It performs the following steps:
/// 1. Queries the local `kinetic-storage` for any locally registered `NameRecord`s.
/// 2. Derives the *current* network time epoch from the `hb_kyn_provider`.
/// 3. Computes the required math against `BEACON_GENESIS`.
/// 4. Generates a signed `Heartbeat` packet containing the Time Oracle's signature.
/// 5. Injects the packet into the Libp2p Swarm via the `hb_network` client, which floods it
///    to the `_kinetic_domain_liveness` Gossipsub topic.
pub fn start_heartbeat_loop(
    hb_storage: Arc<dyn StorageEngine>,
    hb_network: kinetic_network::NetworkClient,
    hb_kyn_provider: Arc<dyn KynProvider>,
    p2p_only: bool,
    initial_kyn: u64,
    daemon_keypair_hb: kinetic_primitives::keypairs::IdentityPrivKey,
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
                if let Ok(latest) = hb_kyn_provider.load_cached() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let expected_kyn = now - kinetic_core::constants::BEACON_GENESIS;

                    if expected_kyn > latest.kyn() + 5 {
                        let err = kinetic_core::error::KynProviderError::P2pFallbackTriggered {
                            behind: expected_kyn.saturating_sub(latest.kyn()),
                        };
                        tracing::warn!(error_code = err.code(), "{}", err);
                        should_fetch_http = true;
                    }
                } else {
                    should_fetch_http = true;
                }
            }

            let kyn = if should_fetch_http {
                match hb_kyn_provider.fetch_latest().await {
                    Ok(p) => {
                        if !p.is_unavailable && !p.is_from_cache {
                            let _ = kyn_tx_hb.send(p.kyn());
                            if !p2p_only && let Ok(payload) = serde_json::to_vec(&p) {
                                let mut envelope =
                                    vec![kinetic_types::network::NetworkOpcode::Kyn as u8];
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
                    Err(_) => hb_kyn_provider
                        .load_cached()
                        .unwrap_or(kinetic_kyn::beacon::RawKyn::unavailable()),
                }
            } else {
                hb_kyn_provider
                    .load_cached()
                    .unwrap_or(kinetic_kyn::beacon::RawKyn::unavailable())
            };

            if kyn.is_unavailable {
                continue;
            }

            if kyn.kyn() > lklr.load(Ordering::Relaxed) {
                lklr.store(kyn.kyn(), Ordering::Relaxed);
            }

            let current_live = lklr.load(Ordering::Relaxed);
            if !kyn.can_heartbeat(kinetic_kyn::types::Kyn(current_live)) {
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
                        latest_kyn: kinetic_kyn::types::Kyn(kyn.kyn()),
                        owner_signature: kinetic_primitives::keypairs::IdentitySignature(vec![]),
                        authorization: None,
                    };

                    let signable_bytes =
                        heartbeat.signable_bytes(kinetic_core::constants::NETWORK_SALT);
                    let keypair = daemon_keypair_hb.clone();
                    let sig_bytes =
                        tokio::task::spawn_blocking(move || keypair.sign(&signable_bytes))
                            .await
                            .unwrap();

                    heartbeat.owner_signature =
                        kinetic_primitives::keypairs::IdentitySignature(sig_bytes.0);

                    let name_clone = name.clone();
                    let hb_network_clone = hb_network.clone();
                    let _kyn_kyn = kyn.kyn();

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
