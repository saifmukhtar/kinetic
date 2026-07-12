use anyhow::Result;
use ed25519_dalek::SigningKey;
use kinetic_core::traits::StorageEngine;
use kinetic_storage::SledStorage;
use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

use std::collections::VecDeque;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub async fn start_nostr_listener(
    daemon_keypair: SigningKey,
    storage: Arc<SledStorage>,
    public_miner: bool,
) -> Result<()> {
    // 1. Load or Derive Nostr Keys
    let base_dir = kinetic_core::config::get_base_dir();
    let nostr_dir = base_dir.join("nostr");
    let private_key_path = nostr_dir.join("private.key");
    let public_key_path = nostr_dir.join("public.key");

    let keys = if private_key_path.exists() {
        let nsec_str = fs::read_to_string(&private_key_path)?.trim().to_string();
        let secret_key = SecretKey::from_bech32(nsec_str)?;
        let loaded_keys = Keys::new(secret_key);
        tracing::info!("📡 Nostr Listener: Loaded existing key from disk.");
        loaded_keys
    } else {
        // Derive secp256k1 SecretKey from the ed25519 secret seed using a domain-separated hash
        let secret_bytes = daemon_keypair.to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(b"kinetic_nostr_secp256k1");
        hasher.update(secret_bytes);
        let secp_seed = hasher.finalize();

        let secret_key = SecretKey::from_slice(&secp_seed)?;
        let derived_keys = Keys::new(secret_key);

        // Save them to disk securely
        fs::create_dir_all(&nostr_dir)?;
        if let Ok(metadata) = fs::metadata(&nostr_dir) {
            let mut perms = metadata.permissions();
            #[cfg(unix)]
            perms.set_mode(0o700); // Only owner can rwx
            let _ = fs::set_permissions(&nostr_dir, perms);
        }

        let nsec_str = derived_keys.secret_key().to_bech32()?;
        let npub_str = derived_keys.public_key().to_bech32()?;

        fs::write(&private_key_path, nsec_str)?;
        if let Ok(metadata) = fs::metadata(&private_key_path) {
            let mut perms = metadata.permissions();
            #[cfg(unix)]
            perms.set_mode(0o600); // Only owner can rw
            let _ = fs::set_permissions(&private_key_path, perms);
        }

        fs::write(&public_key_path, npub_str)?;
        if let Ok(metadata) = fs::metadata(&public_key_path) {
            let mut perms = metadata.permissions();
            #[cfg(unix)]
            perms.set_mode(0o644); // Owner rw, others r
            let _ = fs::set_permissions(&public_key_path, perms);
        }

        tracing::info!("📡 Nostr Listener: Derived new key and saved to disk.");
        derived_keys
    };

    let npub = keys.public_key().to_bech32()?;
    tracing::info!("📡 Public Node Address: {}", npub);

    let tofu_key = b"kinetic_trusted_mobile_pubkey";
    if !public_miner {
        if let Ok(None) = storage.get(tofu_key) {
            tracing::info!("🔒 TOFU active: Waiting for first mobile app to pair...");
        }
    } else {
        tracing::info!("🌍 Public Miner mode active! Accepting jobs from all Nostr clients.");
    }

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

    if public_miner {
        let keys_clone = keys.clone();
        let client_clone = client.clone();
        tokio::spawn(async move {
            loop {
                if let Ok(event) = EventBuilder::new(
                    Kind::TextNote,
                    "Kinetic Public Miner",
                    [Tag::hashtag("kinetic-miner")],
                )
                .to_event(&keys_clone)
                {
                    let _ = client_clone.send_event(event).await;
                    tracing::info!("📢 Broadcasted public miner presence to Nostr relays");
                }
                sleep(Duration::from_secs(3600)).await;
            }
        });
    }



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
                    if processed_events_queue.len() > 100000 {
                        if let Some(old_id) = processed_events_queue.pop_front() {
                            processed_events_set.remove(&old_id);
                        }
                    }

                    let sender = event.pubkey;

                    // Decrypt content
                    let _decrypted =
                        match nip04::decrypt(keys.secret_key(), &sender, event.content.clone()) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };

                    tracing::warn!("Received EncryptedDirectMessage but VDF Mempool logic is disabled.");
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

