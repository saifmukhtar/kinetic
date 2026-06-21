use axum::{
    routing::post,
    Router,
    Json,
    extract::State,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use tracing::{info, error};
use kinetic_network::network::NetworkClient;
use kinetic_core::types::Reveal;
use kinetic_storage::SledStorage;
use std::sync::Arc;
use kinetic_core::traits::StorageEngine;

#[derive(Clone)]
pub struct ApiState {
    pub network: NetworkClient,
    pub storage: Arc<SledStorage>,
}

#[derive(Deserialize, Debug)]
pub struct PublishRequest {
    pub reveal: Reveal,
}

#[derive(Deserialize, Debug)]
pub struct PublishHibernationRequest {
    pub hibernation: kinetic_core::types::Hibernation,
}

#[derive(Serialize)]
pub struct PublishResponse {
    pub status: String,
    pub message: String,
}

pub async fn start_server(network: NetworkClient, storage: Arc<SledStorage>, port: u16) -> anyhow::Result<()> {
    let state = ApiState { network, storage };

    let app = Router::new()
        .route("/publish", post(handle_publish))
        .route("/publish-hibernation", post(handle_publish_hibernation))
        .with_state(state);

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Local Daemon API listening on http://{}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_publish(
    State(state): State<ApiState>,
    Json(req): Json<PublishRequest>,
) -> Result<Json<PublishResponse>, (StatusCode, String)> {
    info!("Received API publish request for name: {}", req.reveal.name);
    
    // Normalize to FQDN format
    let fqdn = if !req.reveal.name.ends_with(".kin.") {
        if req.reveal.name.ends_with(".kin") {
            format!("{}.", req.reveal.name)
        } else {
            format!("{}.kin.", req.reveal.name)
        }
    } else {
        req.reveal.name.clone()
    };
    // Ensure the Reveal internally matches the normalized name exactly
    let mut reveal = req.reveal;
    reveal.name = fqdn.clone();

    let payload_bytes = match serde_json::to_vec(&reveal) {
        Ok(b) => b,
        Err(e) => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Serialization failed: {}", e)));
        }
    };

    match state.network.publish_redundant_payload(&fqdn, payload_bytes).await {
        Ok(_) => {
            info!("Successfully queued payload for {} to the DHT network", fqdn);
            
            // Persist the owned name to embedded storage so the Heartbeat loop can maintain it
            let owned_key = b"kinetic_owned_names";
            let mut owned_names: Vec<String> = match state.storage.get(owned_key) {
                Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
                _ => Vec::new(),
            };
            if !owned_names.contains(&fqdn) {
                owned_names.push(fqdn.clone());
                if let Ok(new_bytes) = serde_json::to_vec(&owned_names) {
                    let _ = state.storage.put(owned_key, &new_bytes);
                    info!("Persisted {} to daemon storage for automatic Heartbeats", fqdn);
                }
            }

            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "Payload accepted and routed to DHT".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to publish to DHT: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to publish: {}", e)))
        }
    }
}

async fn handle_publish_hibernation(
    State(state): State<ApiState>,
    Json(req): Json<PublishHibernationRequest>,
) -> Result<Json<PublishResponse>, (StatusCode, String)> {
    info!("Received API publish hibernation request for name: {}", req.hibernation.name);
    
    let fqdn = req.hibernation.name.clone();
    let payload_bytes = match serde_json::to_vec(&req.hibernation) {
        Ok(b) => b,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Serialization failed: {}", e))),
    };

    match state.network.publish_redundant_payload(&fqdn, payload_bytes).await {
        Ok(_) => {
            info!("Successfully queued Hibernation VDF for {} to the DHT network", fqdn);
            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "Hibernation accepted and routed to DHT".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to publish Hibernation to DHT: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to publish: {}", e)))
        }
    }
}
