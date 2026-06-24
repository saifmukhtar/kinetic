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
        .route("/commit", post(handle_commit))
        .route("/publish", post(handle_publish))
        .route("/publish-hibernation", post(handle_publish_hibernation))
        .route("/publish-kid", post(handle_publish_kid))
        .route("/publish-manifest", post(handle_publish_manifest))
        .route("/resolve-kid/{did}", axum::routing::get(handle_resolve_kid))
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

    let payload_clone = payload_bytes.clone();

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

            // Phase 4.2: Spawn a background task to verify quorum threshold
            let network = state.network.clone();
            let fqdn_clone = fqdn.clone();
            tokio::spawn(async move {
                // Wait briefly for DHT propagation
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                match network.verify_quorum(&fqdn_clone, payload_clone).await {
                    Ok(quorum) if quorum >= 3 => tracing::info!("Quorum reached for {}: {}/5 nodes confirmed.", fqdn_clone, quorum),
                    Ok(quorum) => tracing::warn!("Quorum failed for {}: only {}/5 nodes confirmed storage.", fqdn_clone, quorum),
                    Err(e) => tracing::warn!("Quorum check failed for {}: {}", fqdn_clone, e),
                }
            });

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

    match state.network.publish_redundant_payload(&fqdn, payload_bytes.clone()).await {
        Ok(_) => {
            info!("Successfully queued Hibernation VDF for {} to the DHT network", fqdn);
            
            // Phase 4.2: Spawn a background task to verify quorum threshold
            let network = state.network.clone();
            let fqdn_clone = fqdn.clone();
            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                match network.verify_quorum(&fqdn_clone, payload_bytes).await {
                    Ok(quorum) if quorum >= 3 => tracing::info!("Quorum reached for hibernation of {}: {}/5 nodes confirmed.", fqdn_clone, quorum),
                    Ok(quorum) => tracing::warn!("Quorum failed for hibernation of {}: only {}/5 nodes confirmed storage.", fqdn_clone, quorum),
                    Err(e) => tracing::warn!("Quorum check failed for hibernation of {}: {}", fqdn_clone, e),
                }
            });

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

async fn handle_commit(
    State(state): State<ApiState>,
    Json(req): Json<kinetic_core::types::CommitRequest>,
) -> Result<Json<PublishResponse>, (StatusCode, String)> {
    info!("Received API commit request for name: {}", req.name);
    
    // Normalize to FQDN format
    let fqdn = if !req.name.ends_with(".kin.") {
        if req.name.ends_with(".kin") {
            format!("{}.", req.name)
        } else {
            format!("{}.kin.", req.name)
        }
    } else {
        req.name.clone()
    };

    let payload_bytes = match serde_json::to_vec(&req.commitment) {
        Ok(b) => b,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Serialization failed: {}", e))),
    };

    // The commitment is stored as a special JSON payload (which the network differentiates based on struct parsing)
    // and broadcast to the same 5 derived DHT keys.
    match state.network.publish_redundant_payload(&fqdn, payload_bytes.clone()).await {
        Ok(_) => {
            info!("Successfully queued Commitment for {} to the DHT network", fqdn);
            
            // Phase 4.2: Spawn a background task to verify quorum threshold
            let network = state.network.clone();
            let fqdn_clone = fqdn.clone();
            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                match network.verify_quorum(&fqdn_clone, payload_bytes).await {
                    Ok(quorum) if quorum >= 3 => tracing::info!("Quorum reached for commitment of {}: {}/5 nodes confirmed.", fqdn_clone, quorum),
                    Ok(quorum) => tracing::warn!("Quorum failed for commitment of {}: only {}/5 nodes confirmed storage.", fqdn_clone, quorum),
                    Err(e) => tracing::warn!("Quorum check failed for commitment of {}: {}", fqdn_clone, e),
                }
            });

            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "Commitment accepted and routed to DHT".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to publish Commitment to DHT: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to publish: {}", e)))
        }
    }
}

async fn handle_publish_kid(
    State(state): State<ApiState>,
    Json(kid): Json<kinetic_kid::KidDocument>,
) -> Result<Json<PublishResponse>, (StatusCode, String)> {
    info!("Received API publish request for KID: {}", kid.kid.as_str());

    // 1. Verify the KID document mathematically
    if let Err(e) = kid.verify() {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid KID signature: {}", e)));
    }

    // 2. Serialize and Publish to DHT
    let payload_bytes = serde_json::to_vec(&kid).unwrap();
    let fqdn = kid.kid.as_str().to_string(); // Use DID as the DHT key
    
    match state.network.publish_redundant_payload(&fqdn, payload_bytes).await {
        Ok(_) => {
            info!("Successfully published KID {} to the DHT", fqdn);
            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "KID accepted and routed to DHT".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to publish KID to DHT: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to publish: {}", e)))
        }
    }
}

async fn handle_publish_manifest(
    State(state): State<ApiState>,
    Json(manifest): Json<kinetic_kid::CapabilityManifest>,
) -> Result<Json<PublishResponse>, (StatusCode, String)> {
    let did_str = manifest.kid.as_str();
    info!("Received API publish request for Manifest of KID: {}", did_str);

    // 1. Resolve the KID Document from DHT to verify against
    let kid_payload = match state.network.resolve_redundant_payload(did_str).await {
        Ok(Some(p)) => p,
        Ok(None) => return Err((StatusCode::NOT_FOUND, "KID not found on the network".to_string())),
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("DHT lookup failed: {}", e))),
    };

    let kid_doc: kinetic_kid::KidDocument = match serde_json::from_slice(&kid_payload) {
        Ok(doc) => doc,
        Err(_) => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Invalid KID payload on DHT".to_string())),
    };

    // 2. Verify the manifest against the registered KID
    if let Err(e) = manifest.verify(&kid_doc) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid Manifest signature: {}", e)));
    }

    // 3. Serialize and Publish to DHT under the derived manifest key
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("{}#manifest", did_str).as_bytes());
    let manifest_key = hex::encode(hasher.finalize());

    let payload_bytes = serde_json::to_vec(&manifest).unwrap();
    match state.network.publish_redundant_payload(&manifest_key, payload_bytes).await {
        Ok(_) => {
            info!("Successfully published Manifest for {} to the DHT", did_str);
            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "Manifest accepted and routed to DHT".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to publish Manifest to DHT: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to publish: {}", e)))
        }
    }
}

use axum::extract::Path;

async fn handle_resolve_kid(
    State(state): State<ApiState>,
    Path(did): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    info!("Resolving KID via API: {}", did);

    // Resolve KID
    let kid_payload = match state.network.resolve_redundant_payload(&did).await {
        Ok(Some(p)) => p,
        Ok(None) => return Err((StatusCode::NOT_FOUND, "KID not found".to_string())),
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("DHT error: {}", e))),
    };
    
    let kid_doc: kinetic_kid::KidDocument = serde_json::from_slice(&kid_payload)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid KID data".to_string()))?;

    // Try to resolve Manifest
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("{}#manifest", did).as_bytes());
    let manifest_key = hex::encode(hasher.finalize());

    let mut response = serde_json::json!({
        "kid_document": kid_doc,
    });

    if let Ok(Some(man_payload)) = state.network.resolve_redundant_payload(&manifest_key).await {
        if let Ok(manifest) = serde_json::from_slice::<kinetic_kid::CapabilityManifest>(&man_payload) {
            response["manifest_document"] = serde_json::to_value(manifest).unwrap();
        }
    }

    Ok(Json(response))
}
