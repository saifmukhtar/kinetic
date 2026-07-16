#![allow(missing_docs)]
use js_sys::Function;
use kinetic_network::client::{NetworkConfig, NetworkMode};
use kinetic_network::NetworkEventLoop;
use kinetic_storage::SledStorage;
use libp2p::identity::Keypair;
use std::sync::Arc;
use tokio::sync::watch;
use wasm_bindgen::prelude::*;

/// A WebAssembly wrapper for the Kinetic network client.
///
/// This struct allows a browser environment to initialize a lightweight
/// Kinetic network node, resolve domains, and proxy requests through the P2P network.
#[wasm_bindgen]
pub struct KineticNode {
    #[wasm_bindgen(skip)]
    pub client: Option<kinetic_network::client::NetworkClient>,
    on_event: Function,
}

struct DummyVdfEngine;
impl kinetic_core::traits::VdfEngine for DummyVdfEngine {
    fn evaluate(
        &self,
        _challenge: &kinetic_core::types::Commitment,
        _iterations: u64,
    ) -> Result<kinetic_core::types::VdfProof, kinetic_core::error::VdfError> {
        Err(kinetic_core::error::VdfError::ProofGenerationError)
    }

    fn verify(
        &self,
        _challenge: &kinetic_core::types::Commitment,
        _proof: &kinetic_core::types::VdfProof,
        _iterations: u64,
    ) -> Result<bool, kinetic_core::error::VdfError> {
        Ok(false)
    }
}

#[wasm_bindgen]
impl KineticNode {
    /// Creates a new uninitialized `KineticNode` instance.
    ///
    /// Accepts a JavaScript callback function to emit status events back to the browser.
    ///
    /// # Errors
    /// Returns a `JsValue` error if initialization fails.
    #[wasm_bindgen(constructor)]
    pub fn new(on_event: Function) -> Result<KineticNode, JsValue> {
        console_error_panic_hook::set_once();
        Ok(KineticNode {
            client: None,
            on_event,
        })
    }

    /// Starts the node's background event loop and P2P network client.
    ///
    /// This method sets up an in-memory storage, generates a local Ed25519 identity,
    /// configures a light client network mode, and spawns the event loop onto the
    /// browser's microtask queue.
    ///
    /// # Errors
    /// Returns a `JsValue` error if storage initialization, network configuration,
    /// or event loop startup fails.
    #[wasm_bindgen]
    pub fn start(&mut self) -> Result<(), JsValue> {
        self.emit_event("status", "Starting Kinetic Wasm Node...");

        // 1. Generate local keypair
        let local_key = Keypair::generate_ed25519();

        // 2. Setup in-memory temporary storage
        let storage =
            Arc::new(SledStorage::new_temp().map_err(|e| JsValue::from_str(&e.to_string()))?);

        // 3. Fake drand pulse receiver (for now, since Drand is not fully mocked out in the event loop for Wasm)
        let (_drand_tx, drand_rx) = watch::channel(0);

        // 4. Create NetworkConfig
        let config = NetworkConfig {
            mode: NetworkMode::LightClient,
            listen_addr: libp2p::Multiaddr::empty(),
            bootstrap_nodes: vec![],
            initial_drand_pulse: 0,
            seed_domains: vec![],
            external_address: None,
            max_reveals_per_hour: 100,
            lru_cache_size: std::num::NonZeroUsize::new(10_000).unwrap(),
            disable_pow: false,
            enable_mdns: false,
        };

        // 5. Initialize the Event Loop
        let vdf_engine = Arc::new(DummyVdfEngine);
        let (client, event_loop) =
            NetworkEventLoop::new(config, local_key, storage, drand_rx, None, None, vdf_engine)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

        self.client = Some(client);

        self.emit_event(
            "status",
            "Node event loop initialized. Spawning in background...",
        );

        // 6. Spawn the event loop on the browser's microtask queue!
        wasm_bindgen_futures::spawn_local(async move {
            event_loop.run().await;
        });

        self.emit_event("status", "Node started successfully");
        Ok(())
    }

    fn emit_event(&self, event_type: &str, data: &str) {
        let this = JsValue::null();
        let ev_type = JsValue::from_str(event_type);
        let ev_data = JsValue::from_str(data);
        let _ = self.on_event.call2(&this, &ev_type, &ev_data);
    }

    /// Resolves a domain name across the P2P network to fetch its `DnsZone` configuration.
    ///
    /// This queries the network for a redundant payload associated with the domain
    /// and parses the revealed `DnsZone` into a JavaScript object.
    ///
    /// # Errors
    /// Returns a `JsValue` error if the node is not started, the domain resolution fails,
    /// the payload is invalid, or the zone format cannot be parsed/serialized.
    #[wasm_bindgen]
    pub async fn resolve_domain(&self, name: String) -> Result<JsValue, JsValue> {
        let client = self
            .client
            .clone()
            .ok_or_else(|| JsValue::from_str("Node not started"))?;
        let key = format!("domain_{}", name);

        let bytes = client
            .resolve_redundant_payload(&key)
            .await
            .map_err(|e| JsValue::from_str(&format!("Resolution failed: {}", e)))?;

        let reveal: kinetic_core::types::Reveal = serde_json::from_slice(&bytes)
            .map_err(|e| JsValue::from_str(&format!("Invalid reveal format: {}", e)))?;

        let zone = kinetic_core::types::DnsZone::parse_payload(&reveal.payload)
            .map_err(|e| JsValue::from_str(&format!("Invalid zone format: {}", e)))?;

        let js_obj = serde_wasm_bindgen::to_value(&zone)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JS: {}", e)))?;

        Ok(js_obj)
    }

    /// Sends an HTTP GET proxy request over the P2P network to a specific node.
    ///
    /// Connects to the given `PeerId` and requests the specified path, returning
    /// the raw response bytes as a `Uint8Array`.
    ///
    /// # Errors
    /// Returns a `JsValue` error if the node is not started, the target peer ID is invalid,
    /// or the proxy request fails over the network.
    #[wasm_bindgen]
    pub async fn fetch_proxy(
        &self,
        peer_id_str: String,
        path: String,
    ) -> Result<js_sys::Uint8Array, JsValue> {
        let client = self
            .client
            .clone()
            .ok_or_else(|| JsValue::from_str("Node not started"))?;
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

        let uint8_arr = js_sys::Uint8Array::from(&resp.body[..]);
        Ok(uint8_arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_kinetic_node_initialization() {
        let func = js_sys::Function::new_no_args("return;");
        let node = KineticNode::new(func).unwrap();
        assert!(node.client.is_none());
    }

    #[wasm_bindgen_test]
    async fn test_node_resolve_without_start_fails() {
        let func = js_sys::Function::new_no_args("return;");
        let node = KineticNode::new(func).unwrap();

        let res = node.resolve_domain("test.kin".to_string()).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().as_string().unwrap(), "Node not started");
    }

    #[wasm_bindgen_test]
    async fn test_node_proxy_without_start_fails() {
        let func = js_sys::Function::new_no_args("return;");
        let node = KineticNode::new(func).unwrap();

        let res = node
            .fetch_proxy("12D3KooW...".to_string(), "/path".to_string())
            .await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().as_string().unwrap(), "Node not started");
    }
}
