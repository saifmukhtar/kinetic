use anyhow::Result;
use ed25519_dalek::SigningKey;
use kinetic_core::mempool::Mempool;
use kinetic_core::traits::StorageEngine;
use kinetic_core::types::VdfJobRequest;
use kinetic_storage::SledStorage;
use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};

use std::collections::VecDeque;

pub async fn start_nostr_listener(
    daemon_keypair: SigningKey,
    mempool: Arc<Mutex<Mempool>>,
    storage: Arc<SledStorage>,
) -> Result<()> {
    // 1. Derive secp256k1 SecretKey from the ed25519 secret seed (32 bytes)
    let secret_bytes = daemon_keypair.to_bytes();
    let secret_key = SecretKey::from_slice(&secret_bytes)?;
    let keys = Keys::new(secret_key);

    let npub = keys.public_key().to_bech32()?;
    tracing::info!("📡 Nostr Listener active. Public Node Address: {}", npub);

    // 2. Initialize Nostr Client
    let client = Client::new(&keys);

    // Expanded list of reliable public Nostr relays for resilience (Case 105)
    let relays = vec![
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.nostr.band",
        "wss://relay.snort.social",
        "wss://relay.primal.net",
        "wss://eden.nostr.land",
        "wss://relay.nostr.bg",
        "wss://nostr.fmt.wiz.biz",
        "wss://nostr.mom",
        "wss://nostr.oxtr.dev",
    ];

    for relay in relays {
        let _ = client.add_relay(relay).await;
    }

    client.connect().await;

    // 3. Subscribe to Kind 4 (Encrypted Direct Messages) addressed to us
    let subscription = Filter::new()
        .pubkey(keys.public_key())
        .kind(Kind::EncryptedDirectMessage);

    let _ = client.subscribe(vec![subscription.clone()], None).await;

    // Keep track of pending requests: challenge_hex -> sender_pubkey
    let pending_requests: Arc<Mutex<HashMap<String, PublicKey>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Spawn a task to poll for completed proofs and reply
    let keys_clone = keys.clone();
    let client_clone = client.clone();
    let storage_clone = storage.clone();
    let pending_clone = pending_requests.clone();

    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(5)).await;

            let mut completed = Vec::new();

            {
                let mut pending = pending_clone.lock().unwrap_or_else(|e| e.into_inner());
                for (challenge_hex, sender_pubkey) in pending.iter() {
                    let proof_key = format!("kinetic_delegation_proof:{}", challenge_hex);
                    if let Ok(Some(bytes)) = storage_clone.get(proof_key.as_bytes()) {
                        completed.push((challenge_hex.clone(), *sender_pubkey, bytes));
                    }
                }

                for (challenge_hex, _, _) in &completed {
                    pending.remove(challenge_hex);
                }
            }

            for (_challenge_hex, sender_pubkey, bytes) in completed {
                let proof_hex = hex::encode(&bytes);
                let reply_json = serde_json::json!({
                    "status": "completed",
                    "proof_bytes": proof_hex
                });

                let content = match serde_json::to_string(&reply_json) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                let encrypted_content =
                    match nip04::encrypt(keys_clone.secret_key(), &sender_pubkey, content) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };

                let event_builder = EventBuilder::new(
                    Kind::EncryptedDirectMessage,
                    encrypted_content,
                    [Tag::public_key(sender_pubkey)],
                );

                if let Ok(event) = event_builder.to_event(&keys_clone) {
                    let _ = client_clone.send_event(event).await;
                    tracing::info!(
                        "✅ Sent VDF proof via Nostr NIP-04 to {}",
                        sender_pubkey.to_bech32().unwrap_or_default()
                    );
                }
            }
        }
    });

    // Keep track of recently processed events to prevent replay attacks
    let mut processed_events_set: std::collections::HashSet<EventId> =
        std::collections::HashSet::new();
    let mut processed_events_queue: VecDeque<EventId> = VecDeque::new();

    loop {
        let mut notifications = client.notifications();

        while let Ok(notification) = notifications.recv().await {
            if let RelayPoolNotification::Event { event, .. } = notification {
                if event.kind == Kind::EncryptedDirectMessage {
                    if processed_events_set.contains(&event.id) {
                        continue;
                    }

                    // Add to cache
                    processed_events_set.insert(event.id);
                    processed_events_queue.push_back(event.id);
                    if processed_events_queue.len() > 1000 {
                        if let Some(old_id) = processed_events_queue.pop_front() {
                            processed_events_set.remove(&old_id);
                        }
                    }

                    let sender = event.pubkey;

                    // Decrypt content
                    let decrypted =
                        match nip04::decrypt(keys.secret_key(), &sender, event.content.clone()) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };

                    // Parse VdfJobRequest
                    if let Ok(req) = serde_json::from_str::<VdfJobRequest>(&decrypted) {
                        tracing::info!(
                            "Received VDF Request from {} over Nostr",
                            sender.to_bech32().unwrap_or_default()
                        );

                        // Case 164: Nostr Request Expiration (48-hour cutoff)
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        let genesis = kinetic_core::drand::QUICKNET_GENESIS_TIME;
                        let period = kinetic_core::drand::QUICKNET_PERIOD;
                        let current_pulse = if now > genesis {
                            (now - genesis) / period
                        } else {
                            0
                        };

                        // 48 hours = 172800 seconds / 3 = 57600 pulses
                        if current_pulse > req.drand_pulse
                            && current_pulse - req.drand_pulse > 57600
                        {
                            tracing::warn!(
                                "Rejected VDF Request from {}: Drand pulse is too old (> 48 hours)",
                                sender
                            );
                            continue;
                        }

                        if req.name_length < 8 {
                            continue;
                        }

                        // Verify Hashcash (minimum 20 leading zero bits)
                        let mut hasher = Sha256::new();
                        hasher.update(req.challenge_hash);
                        hasher.update(req.hashcash_nonce.to_le_bytes());
                        let result = hasher.finalize();

                        let valid_hashcash =
                            result[0] == 0 && result[1] == 0 && (result[2] & 0xF0) == 0;
                        if !valid_hashcash {
                            tracing::warn!(
                                "Invalid Hashcash (requires 20 leading zero bits) from {}",
                                sender
                            );
                            continue;
                        }

                        // Task 4: Trust-on-First-Use (TOFU)
                        let tofu_key = b"kinetic_trusted_mobile_pubkey";
                        if let Ok(Some(trusted_bytes)) = storage.get(tofu_key) {
                            if trusted_bytes != sender.to_bytes() {
                                tracing::warn!(
                                    "Rejected VDF Request from untrusted stranger: {}",
                                    sender.to_bech32().unwrap_or_default()
                                );
                                continue;
                            }
                        } else {
                            // Trust this pubkey on first use
                            let _ = storage.put(tofu_key, &sender.to_bytes());
                            tracing::info!(
                                "🔒 TOFU: Paired with mobile pubkey {}",
                                sender.to_bech32().unwrap_or_default()
                            );
                        }

                        let challenge_hex = hex::encode(req.challenge_hash);

                        // [Case 106] Prevent Replay Attacks: Check if VDF is already computed
                        let proof_key = format!("kinetic_delegation_proof:{}", challenge_hex);
                        if let Ok(Some(_)) = storage.get(proof_key.as_bytes()) {
                            tracing::warn!(
                                "Replay attack or duplicate Nostr request dropped: {}",
                                challenge_hex
                            );
                            continue;
                        }

                        let added = {
                            let mut mp = mempool.lock().unwrap_or_else(|e| e.into_inner());
                            mp.add(req)
                        };

                        if added {
                            pending_requests
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(challenge_hex, sender);
                            tracing::info!("Queued VDF Request via Nostr");
                        }
                    }
                }
            }
        }

        tracing::warn!(
            "Nostr notifications channel closed. Reconnecting to relays in 5 seconds..."
        );
        sleep(Duration::from_secs(5)).await;
        client.connect().await;
        let _ = client.subscribe(vec![subscription.clone()], None).await;
    }
}
