use js_sys::Function;
use kinetic_network::client::{NetworkConfig, NetworkMode};
use kinetic_network::NetworkEventLoop;
use kinetic_storage::SledStorage;
use libp2p::identity::Keypair;
use std::sync::Arc;
use tokio::sync::watch;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct KineticNode {
    #[wasm_bindgen(skip)]
    pub client: Option<kinetic_network::client::NetworkClient>,
    on_event: Function,
}

#[wasm_bindgen]
impl KineticNode {
    #[wasm_bindgen(constructor)]
    pub fn new(on_event: Function) -> Result<KineticNode, JsValue> {
        console_error_panic_hook::set_once();
        Ok(KineticNode {
            client: None,
            on_event,
        })
    }

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
            listen_addr: "".to_string(),
            bootstrap_nodes: vec![],
            initial_drand_pulse: 0,
            seed_domains: vec![],
            external_address: None,
            enable_mdns: false,
        };

        // 5. Initialize the Event Loop
        let (client, event_loop) =
            NetworkEventLoop::new(config, local_key, storage, drand_rx, None, None)
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
            method: "GET".to_string(),
            path,
            headers: std::collections::HashMap::new(),
            body: vec![],
        };

        let resp = client
            .send_proxy_request(peer_id, req)
            .await
            .map_err(|e| JsValue::from_str(&format!("Proxy request failed: {:?}", e)))?;

        let uint8_arr = js_sys::Uint8Array::from(&resp.body[..]);
        Ok(uint8_arr)
    }
}
