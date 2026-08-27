#![deny(missing_docs)]
//! # kinetic-wasm
//!
//! WebAssembly browser bindings for the Kinetic P2P network client.
//! Upgraded to a Universal Web3 Extension that dynamically spins up swarms based on the Atlas Registry.

use futures_timer::Delay;
use js_sys::Function;
use kinetic_network::NetworkEventLoop;
use kinetic_network::client::{NetworkClient, NetworkConfig, NetworkMode};
use kinetic_storage::KineticStorage;
use libp2p::identity::Keypair;

use kinetic_core::types::NrsZoneExt;
use kinetic_verify::signatures::VerifySignature;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use wasm_bindgen::prelude::*;

/// Configuration for a specific Kinetic network fork.
#[wasm_bindgen(getter_with_clone)]
#[derive(Clone, serde::Deserialize)]
pub struct AtlasNetworkConfig {
    /// The NSP (e.g. "kin")
    pub id: String,
    /// Display name
    pub name: String,
    /// Network ID used for signatures
    pub network_id: String,
    /// Hardcoded bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
    /// Optional kintree DNS seed domain
    pub seed_domain: Option<String>,
}

struct SwarmHandle {
    client: NetworkClient,
    last_used: f64,
}

/// A Universal WebAssembly wrapper for the Kinetic network client.
/// Dynamically spawns Libp2p swarms for multiple TLDs on-demand.
#[wasm_bindgen]
pub struct UniversalKineticNode {
    registry: Rc<RefCell<HashMap<String, AtlasNetworkConfig>>>,
    swarms: Rc<RefCell<HashMap<String, SwarmHandle>>>,
    on_event: Function,
}

#[wasm_bindgen]
impl UniversalKineticNode {
    /// Creates a new uninitialized `UniversalKineticNode` instance.
    #[wasm_bindgen(constructor)]
    pub fn new(on_event: Function) -> Result<UniversalKineticNode, JsValue> {
        console_error_panic_hook::set_once();
        Ok(UniversalKineticNode {
            registry: Rc::new(RefCell::new(HashMap::new())),
            swarms: Rc::new(RefCell::new(HashMap::new())),
            on_event,
        })
    }

    fn emit_event(&self, event_type: &str, data: &str) {
        let this = JsValue::null();
        let ev_type = JsValue::from_str(event_type);
        let ev_data = JsValue::from_str(data);
        let _ = self.on_event.call2(&this, &ev_type, &ev_data);
    }

    /// Starts the background SwarmManager Garbage Collector.
    #[wasm_bindgen]
    pub fn start_manager(&self) -> Result<(), JsValue> {
        self.emit_event("status", "Starting Swarm GC...");
        let swarms_clone = self.swarms.clone();
        let on_event = self.on_event.clone();

        wasm_bindgen_futures::spawn_local(async move {
            loop {
                Delay::new(Duration::from_secs(60)).await;
                let now = js_sys::Date::now();
                let mut lock = swarms_clone.borrow_mut();
                lock.retain(|nsp, handle| {
                    if now - handle.last_used > 10.0 * 60.0 * 1000.0 {
                        let this = JsValue::null();
                        let _ = on_event.call2(
                            &this,
                            &JsValue::from_str("status"),
                            &JsValue::from_str(&format!("Shutting down idle swarm for {}", nsp)),
                        );
                        false
                    } else {
                        true
                    }
                });
            }
        });

        self.emit_event("status", "SwarmManager GC started successfully");
        Ok(())
    }

    /// Fetches the global Atlas network registry from GitHub index.json.
    #[wasm_bindgen]
    pub async fn fetch_registry(&self) -> Result<(), JsValue> {
        let client = reqwest::Client::new();
        // Fetch the aggregated index.json instead of making multiple API calls
        let url = "https://raw.githubusercontent.com/saifmukhtar/kinetic-atlas/main/index.json";
        let res = client
            .get(url)
            .header("User-Agent", "Universal-Kinetic-Wasm")
            .send()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        // Parse directly as an array of AtlasNetworkConfig
        let networks: Vec<AtlasNetworkConfig> = res
            .json()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let mut registry = self.registry.borrow_mut();
        for config in networks {
            registry.insert(config.id.clone(), config);
        }

        // Fallback injection for .kin if GitHub fetch failed or it's not present
        if !registry.contains_key("kin") {
            registry.insert(
                "kin".to_string(),
                AtlasNetworkConfig {
                    id: "kin".to_string(),
                    name: "Kinetic Mainnet".to_string(),
                    network_id: kinetic_core::constants::NETWORK_ID.to_string(),
                    bootstrap_nodes: vec![],
                    seed_domain: Some("bootstrap.kinetic.network".to_string()),
                },
            );
        }

        self.emit_event(
            "status",
            &format!("Registry synced. Supported TLDs: {}", registry.len()),
        );
        Ok(())
    }

    /// Returns the list of currently supported TLDs as a JavaScript Array of strings.
    #[wasm_bindgen]
    pub fn get_supported_tlds(&self) -> js_sys::Array {
        let registry = self.registry.borrow();
        let arr = js_sys::Array::new_with_length(registry.len() as u32);
        for (i, nsp) in registry.keys().enumerate() {
            arr.set(i as u32, JsValue::from_str(nsp));
        }
        arr
    }

    async fn get_or_spawn_swarm(&self, nsp: &str) -> Result<NetworkClient, JsValue> {
        {
            let mut lock = self.swarms.borrow_mut();
            if let Some(handle) = lock.get_mut(nsp) {
                handle.last_used = js_sys::Date::now();
                return Ok(handle.client.clone());
            }
        }

        let config = {
            let reg = self.registry.borrow();
            reg.get(nsp)
                .cloned()
                .ok_or_else(|| JsValue::from_str(&format!("NSP not found in registry: {}", nsp)))?
        };

        self.emit_event("status", &format!("Spawning new swarm for .{}", nsp));

        let mut bootstrap_nodes = vec![];
        for addr in config.bootstrap_nodes.iter() {
            if let Ok(m) = addr.parse() {
                bootstrap_nodes.push(m);
            }
        }

        if let Some(seed_domain) = &config.seed_domain {
            let resolved = kinetic_network::dns_tree::resolve_dns_tree(seed_domain).await;
            for addr in resolved {
                bootstrap_nodes.push(addr);
            }
        }

        let storage =
            Arc::new(KineticStorage::new_temp().map_err(|e| JsValue::from_str(&e.to_string()))?);
        let (_drand_tx, drand_rx) = watch::channel(0);

        let net_config = NetworkConfig {
            mode: NetworkMode::LightNode,
            listen_addrs: vec![],
            quic_listen_addrs: vec![],
            bootstrap_nodes,
            initial_kyn: 0,
            seed_domain: vec![],
            external_address: None,
            max_reveals_per_hour: 100,
            lru_cache_size: std::num::NonZeroUsize::new(10_000).unwrap(),
            disable_pow: false,
            enable_relay_server: false,
            enable_upnp: false,
            enable_mdns: false,
            test_mode: false,
            disable_storage_sync: false,
        };

        let local_key = Keypair::generate_ed25519();
        let vdf_engine = Arc::new(kinetic_vdf_rsa::RsaVdfEngine::new());
        let (client, event_loop) = NetworkEventLoop::new(
            net_config, local_key, storage, drand_rx, None, None, vdf_engine,
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

        wasm_bindgen_futures::spawn_local(async move {
            event_loop.run().await;
        });

        self.swarms.borrow_mut().insert(
            nsp.to_string(),
            SwarmHandle {
                client: client.clone(),
                last_used: js_sys::Date::now(),
            },
        );

        Ok(client)
    }

    /// Resolves a full domain name (e.g. "mywebsite.kin")
    #[wasm_bindgen]
    pub async fn resolve_domain(&self, full_domain: String) -> Result<JsValue, JsValue> {
        let nsp = full_domain.split('.').next_back().unwrap_or(&full_domain);
        let client = self.get_or_spawn_swarm(nsp).await?;

        let bytes = client
            .resolve_redundant_payload(&full_domain)
            .await
            .map_err(|e| JsValue::from_str(&format!("Resolution failed: {}", e)))?;

        let record: kinetic_core::types::NameRecord = serde_json::from_slice(&bytes)
            .map_err(|e| JsValue::from_str(&format!("Invalid record format: {}", e)))?;

        if record.name() != full_domain {
            return Err(JsValue::from_str("Record name mismatch"));
        }

        // Validate signature against the mathematical network salt
        if record
            .verify_signature(kinetic_core::constants::NETWORK_SALT)
            .is_err()
        {
            return Err(JsValue::from_str("Invalid record signature"));
        }

        let zone = kinetic_core::types::NrsZone::parse_payload(record.payload())
            .map_err(|e| JsValue::from_str(&format!("Invalid zone format: {}", e)))?;

        let js_obj = serde_wasm_bindgen::to_value(&zone)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JS: {}", e)))?;

        Ok(js_obj)
    }

    /// Sends an HTTP GET proxy request over a specific NSP's P2P network.
    #[wasm_bindgen]
    pub async fn fetch_proxy(
        &self,
        nsp: String,
        peer_id_str: String,
        path: String,
    ) -> Result<js_sys::Uint8Array, JsValue> {
        let client = self.get_or_spawn_swarm(&nsp).await?;

        let peer_id: libp2p::PeerId = peer_id_str
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid PeerId: {}", e)))?;

        let req = kinetic_network::client::types::ProxyRequest {
            method: "GET".into(),
            path: path.into(),
            headers: vec![],
            body: bytes::Bytes::new(),
        };

        let resp = client
            .send_proxy_request(peer_id, req)
            .await
            .map_err(|e| JsValue::from_str(&format!("Proxy request failed: {:?}", e)))?;

        Ok(js_sys::Uint8Array::from(&resp.body[..]))
    }
}
