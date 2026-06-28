use axum::{
    routing::post,
    Router,
    Json,
    extract::{State, Path},
    http::StatusCode,
};
use rust_embed::RustEmbed;
use axum::response::IntoResponse;
use axum::http::{header, Uri};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use tracing::{info, error};
use kinetic_network::NetworkClient;
use kinetic_core::types::Reveal;
use kinetic_storage::SledStorage;
use std::sync::{Arc, Mutex};
use kinetic_core::traits::StorageEngine;
use std::collections::HashMap;

#[derive(Clone, Serialize, Deserialize)]
pub struct VdfTaskStatus {
    pub status: String,
    pub iterations: u64,
    pub progress: u64,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct ApiState {
    pub network: NetworkClient,
    pub storage: Arc<SledStorage>,
    pub vdf_tasks: Arc<Mutex<HashMap<String, VdfTaskStatus>>>,
    pub auth_token: String,
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

#[derive(RustEmbed)]
#[folder = "../kinetic-ui/dist"]
struct WebAssets;

async fn static_handler(uri: Uri) -> impl IntoResponse {
    let mut path = uri.path().trim_start_matches('/');
    if path.is_empty() {
        path = "index.html";
    }

    match WebAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            ([(header::CONTENT_TYPE, mime.as_ref())], content.data).into_response()
        }
        None => {
            // Fallback to index.html for SPA router
            if let Some(content) = WebAssets::get("index.html") {
                let mime = mime_guess::from_path("index.html").first_or_octet_stream();
                ([(header::CONTENT_TYPE, mime.as_ref())], content.data).into_response()
            } else {
                (StatusCode::NOT_FOUND, "404 Not Found").into_response()
            }
        }
    }
}

pub fn app(state: ApiState) -> Router {

    let auth_routes = Router::new()
        .route("/commit", post(handle_commit))
        .route("/publish", post(handle_publish))
        .route("/publish-hibernation", post(handle_publish_hibernation))
        .route("/publish-kid", post(handle_publish_kid))
        .route("/publish-manifest", post(handle_publish_manifest))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware));

    let public_api_routes = Router::new()
        .route("/resolve/{name}", axum::routing::get(handle_resolve_name))
        .route("/resolve-kid/{did}", axum::routing::get(handle_resolve_kid))
        .route("/config", axum::routing::get(handle_config))
        .route("/config", axum::routing::post(handle_set_config))
        .route("/owned-names", axum::routing::get(handle_owned_names))
        .route("/zone/{name}", axum::routing::get(handle_get_zone))
        .route("/zone/{name}", axum::routing::post(handle_post_zone))
        .route("/zone/{name}/publish", axum::routing::post(handle_publish_zone))
        .route("/network-status", axum::routing::get(handle_network_status))
        .route("/vdf/register", axum::routing::post(handle_vdf_register))
        .route("/vdf/status/{task_id}", axum::routing::get(handle_vdf_status));

    let api_routes = Router::new()
        .nest("/api", public_api_routes.clone().merge(auth_routes.clone()))
        .merge(public_api_routes)
        .merge(auth_routes);

    Router::new()
        .merge(api_routes)
        .fallback(get(static_handler))
        .with_state(state)
}


pub async fn start_server(network: NetworkClient, storage: Arc<SledStorage>, port: u16) -> anyhow::Result<()> {
    let mut token_bytes = [0u8; 32];
    if getrandom::fill(&mut token_bytes).is_err() {
        tracing::error!("Failed to generate secure API token");
    }
    let token = hex::encode(token_bytes);

    let token_path = kinetic_core::config::get_api_token_path();
    if let Some(parent) = token_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&token_path, &token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(&token_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&token_path, perms);
        }
    }
    
    let state = ApiState { 
        network, 
        storage, 
        vdf_tasks: Arc::new(Mutex::new(HashMap::new())),
        auth_token: token 
    };
    let app = app(state);

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Local Daemon API listening on http://{}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn auth_middleware(
    State(state): State<ApiState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = req.headers().get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(header) if header == format!("Bearer {}", state.auth_token) => {
            Ok(next.run(req).await)
        }
        _ => {
            tracing::warn!("Rejecting unauthorized API request.");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

async fn handle_publish(
    State(state): State<ApiState>,
    Json(req): Json<PublishRequest>,
) -> Result<Json<PublishResponse>, (StatusCode, String)> {
    info!("Received API publish request for name: {}", req.reveal.name);
    
    // Normalize to canonical format
    let fqdn = kinetic_core::types::normalize_name(&req.reveal.name);
    if !kinetic_core::types::is_valid_apex_name(&fqdn) {
        return Err((StatusCode::BAD_REQUEST, "Invalid domain name. You can only register apex domains (e.g. 'saif.kin'). Subdomains are strictly routed dynamically at the DNS/Proxy level.".to_string()));
    }
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

            // Phase 4.2: Verify quorum threshold before returning
            let network = state.network.clone();
            let fqdn_clone = fqdn.clone();
            
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            match network.verify_quorum(&fqdn_clone, payload_clone).await {
                Ok(quorum) if quorum >= 3 => {
                    tracing::info!("Quorum reached for {}: {}/5 nodes confirmed.", fqdn_clone, quorum);
                    Ok(Json(PublishResponse {
                        status: "success".to_string(),
                        message: format!("Payload accepted and confirmed by {}/5 nodes.", quorum),
                    }))
                }
                Ok(quorum) => {
                    tracing::warn!("Quorum failed for {}: only {}/5 nodes confirmed storage.", fqdn_clone, quorum);
                    Err((StatusCode::BAD_GATEWAY, format!("Quorum failed: only {}/5 nodes confirmed", quorum)))
                }
                Err(e) => {
                    tracing::warn!("Quorum check failed for {}: {}", fqdn_clone, e);
                    Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Quorum check error: {}", e)))
                }
            }
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
    
    // Normalize to canonical format
    let fqdn = kinetic_core::types::normalize_name(&req.name);
    if !kinetic_core::types::is_valid_apex_name(&fqdn) {
        return Err((StatusCode::BAD_REQUEST, "Invalid domain name. You can only commit to apex domains (e.g. 'saif.kin').".to_string()));
    }

    let payload_bytes = match serde_json::to_vec(&req.commitment) {
        Ok(b) => b,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Serialization failed: {}", e))),
    };

    // The commitment is stored as a special JSON payload (which the network differentiates based on struct parsing)
    // and broadcast to the same 5 derived DHT keys.
    match state.network.publish_redundant_payload(&fqdn, payload_bytes.clone()).await {
        Ok(_) => {
            info!("Successfully queued Commitment for {} to the DHT network", fqdn);
            
            // Phase 4.2: Verify quorum threshold before returning
            let network = state.network.clone();
            let fqdn_clone = fqdn.clone();
            
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            match network.verify_quorum(&fqdn_clone, payload_bytes).await {
                Ok(quorum) if quorum >= 3 => {
                    tracing::info!("Quorum reached for commitment of {}: {}/5 nodes confirmed.", fqdn_clone, quorum);
                    Ok(Json(PublishResponse {
                        status: "success".to_string(),
                        message: format!("Commitment accepted and confirmed by {}/5 nodes.", quorum),
                    }))
                }
                Ok(quorum) => {
                    tracing::warn!("Quorum failed for commitment of {}: only {}/5 nodes confirmed storage.", fqdn_clone, quorum);
                    Err((StatusCode::BAD_GATEWAY, format!("Quorum failed: only {}/5 nodes confirmed", quorum)))
                }
                Err(e) => {
                    tracing::warn!("Quorum check failed for commitment of {}: {}", fqdn_clone, e);
                    Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Quorum check error: {}", e)))
                }
            }
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
    let payload_bytes = match serde_json::to_vec(&kid) {
        Ok(b) => b,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Serialization failed: {}", e))),
    };
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

    let payload_bytes = match serde_json::to_vec(&manifest) {
        Ok(b) => b,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Serialization failed: {}", e))),
    };
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

async fn handle_resolve_name(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<kinetic_core::types::Reveal>, (StatusCode, String)> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    
    match state.network.resolve_redundant_payload(&fqdn).await {
        Ok(Some(payload)) => {
            match serde_json::from_slice::<kinetic_core::types::Reveal>(&payload) {
                Ok(reveal) => Ok(Json(reveal)),
                Err(_) => Err((StatusCode::INTERNAL_SERVER_ERROR, "Invalid Reveal payload on DHT".to_string())),
            }
        }
        Ok(None) => Err((StatusCode::NOT_FOUND, format!("Name {} not found", fqdn))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("DHT lookup failed: {}", e))),
    }
}

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
            if let Ok(val) = serde_json::to_value(manifest) {
                response["manifest_document"] = val;
            }
        }
    }

    Ok(Json(response))
}

async fn handle_config(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let config = kinetic_core::config::KineticConfig::load();
    Json(serde_json::json!({
        "token": state.auth_token,
        "mode": config.daemon.network_mode
    }))
}

async fn handle_owned_names(State(state): State<ApiState>) -> Json<Vec<String>> {
    let owned_key = b"kinetic_owned_names";
    let owned_names: Vec<String> = match state.storage.get(owned_key) {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
        _ => Vec::new(),
    };
    Json(owned_names)
}

async fn handle_network_status(State(state): State<ApiState>) -> Json<serde_json::Value> {
    match state.network.get_network_status().await {
        Ok(status) => Json(status),
        Err(e) => Json(serde_json::json!({
            "status": format!("Error: {}", e),
            "peers": 0,
            "dht_size": 0,
            "uptime": "Unknown"
        }))
    }
}

async fn handle_set_config(State(_state): State<ApiState>, Json(payload): Json<serde_json::Value>) -> Json<serde_json::Value> {
    let mut config = kinetic_core::config::KineticConfig::load();
    if let Some(mode) = payload.get("mode").and_then(|m| m.as_str()) {
        config.daemon.network_mode = mode.to_string();
    }
    let _ = config.save();
    Json(serde_json::json!({"status": "ok", "message": "Configuration saved. Restart daemon to apply."}))
}

#[derive(Deserialize)]
struct VdfRegisterRequest {
    name: String,
    iterations: Option<u64>,
}

async fn handle_vdf_register(State(state): State<ApiState>, Json(req): Json<VdfRegisterRequest>) -> Json<serde_json::Value> {
    let fqdn = kinetic_core::types::normalize_name(&req.name);
    let task_id = uuid::Uuid::new_v4().to_string();
    
    // Store initial task state
    {
        let mut tasks = state.vdf_tasks.lock().unwrap();
        tasks.insert(task_id.clone(), VdfTaskStatus {
            status: "Initializing".to_string(),
            iterations: req.iterations.unwrap_or(100_000), // Default lower for testing in UI
            progress: 0,
            error: None,
        });
    }

    // Spawn blocking background task
    let tasks_clone = state.vdf_tasks.clone();
    let network_clone = state.network.clone();
    let storage_clone = state.storage.clone();
    let task_id_clone = task_id.clone();
    let iterations = req.iterations.unwrap_or(100_000);

    tokio::spawn(async move {
        // Step 1: Drand
        update_task_status(&tasks_clone, &task_id_clone, "Fetching Drand beacon", 10);
        let drand_client = kinetic_core::drand::DrandClient::new(storage_clone.clone());
        let drand_data = match drand_client.fetch_latest().await {
            Ok(d) => d,
            Err(e) => {
                update_task_error(&tasks_clone, &task_id_clone, format!("Drand error: {}", e));
                return;
            }
        };

        // Step 2: Commitment
        update_task_status(&tasks_clone, &task_id_clone, "Generating Commitment", 20);
        let keypair = match kinetic_core::types::load_or_create_keypair() {
            Ok(k) => k,
            Err(e) => {
                update_task_error(&tasks_clone, &task_id_clone, format!("Keypair error: {}", e));
                return;
            }
        };
        let pubkey = keypair.verifying_key().to_bytes();
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt).expect("Failed to generate random salt");
        let challenge_bytes = hex::decode(&drand_data.randomness).unwrap_or_else(|_| vec![0u8; 32]);
        
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(fqdn.as_bytes());
        hasher.update(&salt);
        hasher.update(&challenge_bytes);
        hasher.update(&pubkey);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        let challenge = kinetic_core::types::Commitment { hash };

        // Post commitment to DHT via internal network client
        update_task_status(&tasks_clone, &task_id_clone, "Broadcasting Commitment", 30);
        

        let _commit_req = kinetic_core::types::CommitRequest {
            name: fqdn.clone(),
            commitment: challenge.clone(),
        };
        // We'll skip sending the literal HTTP commit request internally, and just broadcast it directly to DHT:
        let commit_bytes = serde_json::to_vec(&challenge).unwrap();
        if let Err(e) = network_clone.publish_redundant_payload(&fqdn, commit_bytes).await {
             update_task_error(&tasks_clone, &task_id_clone, format!("DHT Commit Error: {}", e));
             return;
        }

        // Step 3: VDF Evaluation (Blocking)
        update_task_status(&tasks_clone, &task_id_clone, "Computing VDF... (This may take a few minutes)", 40);
        let required_iters = kinetic_core::consensus_math::ConsensusParams::default().required_iterations(&fqdn, drand_data.round, &pubkey);
        let actual_iterations = std::cmp::max(iterations, required_iters);

        let vdf_engine = kinetic_vdf::ChiaVdfEngine::new();
        let challenge_clone = challenge.clone();
        
        // Spawn blocking to not starve tokio executor
        let proof = match tokio::task::spawn_blocking(move || {
            use kinetic_core::traits::VdfEngine;
            vdf_engine.evaluate(&challenge_clone, actual_iterations)
        }).await {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                update_task_error(&tasks_clone, &task_id_clone, format!("VDF engine error: {}", e));
                return;
            }
            Err(e) => {
                update_task_error(&tasks_clone, &task_id_clone, format!("Task panic: {}", e));
                return;
            }
        };

        update_task_status(&tasks_clone, &task_id_clone, "Publishing Registration", 90);

        // Construct Reveal
        let records = HashMap::new();
        let zone = kinetic_core::types::DnsZone { records };
        let payload = serde_json::to_vec(&zone).unwrap();
        
        let mut reveal = kinetic_core::types::Reveal {
            protocol_version: 2,
            name: fqdn.clone(),
            payload,
            salt,
            drand_pulse: drand_data.round,
            drand_randomness: drand_data.randomness.clone(),
            iterations: actual_iterations,
            vdf_proof: kinetic_core::types::VdfProof { proof_bytes: proof.proof_bytes },
            pubkey: pubkey.to_vec(),
            signature: vec![],
        };
        
        use ed25519_dalek::Signer;
        let signable = reveal.signable_bytes();
        reveal.signature = keypair.sign(&signable).to_bytes().to_vec();

        // Publish to Network
        let reveal_bytes = serde_json::to_vec(&reveal).unwrap();
        if let Err(e) = network_clone.publish_redundant_payload(&fqdn, reveal_bytes).await {
            update_task_error(&tasks_clone, &task_id_clone, format!("DHT Publish Error: {}", e));
            return;
        }

        // Save to internal storage so Dashboard can see it
        let mut owned = Vec::new();
        if let Ok(Some(bytes)) = storage_clone.get(b"kinetic_owned_names") {
            if let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes) {
                owned = names;
            }
        }
        if !owned.contains(&fqdn) {
            owned.push(fqdn.clone());
            let _ = storage_clone.put(b"kinetic_owned_names", &serde_json::to_vec(&owned).unwrap());
        }

        // Save default zone file
        let zones_dir = kinetic_core::config::get_zones_dir();
        let _ = std::fs::create_dir_all(&zones_dir);
        let path = zones_dir.join(format!("{}.json", fqdn));
        let _ = std::fs::write(path, serde_json::to_string_pretty(&zone).unwrap());

        update_task_status(&tasks_clone, &task_id_clone, "Complete", 100);
    });

    Json(serde_json::json!({
        "task_id": task_id,
        "message": "VDF generation started"
    }))
}

fn update_task_status(tasks: &Arc<Mutex<HashMap<String, VdfTaskStatus>>>, id: &str, status: &str, progress: u64) {
    if let Ok(mut map) = tasks.lock() {
        if let Some(task) = map.get_mut(id) {
            task.status = status.to_string();
            task.progress = progress;
        }
    }
}

fn update_task_error(tasks: &Arc<Mutex<HashMap<String, VdfTaskStatus>>>, id: &str, err: String) {
    if let Ok(mut map) = tasks.lock() {
        if let Some(task) = map.get_mut(id) {
            task.error = Some(err);
            task.status = "Failed".to_string();
        }
    }
}

async fn handle_vdf_status(Path(task_id): Path<String>, State(state): State<ApiState>) -> Json<serde_json::Value> {
    let task = {
        let tasks = state.vdf_tasks.lock().unwrap();
        tasks.get(&task_id).cloned()
    };
    
    match task {
        Some(t) => Json(serde_json::to_value(t).unwrap()),
        None => Json(serde_json::json!({"error": "Task not found"})),
    }
}

async fn handle_get_zone(Path(name): Path<String>) -> Json<serde_json::Value> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    let path = kinetic_core::config::get_zones_dir().join(format!("{}.json", fqdn));
    if let Ok(content) = std::fs::read_to_string(path) {
        if let Ok(zone) = serde_json::from_str::<serde_json::Value>(&content) {
            return Json(zone);
        }
    }
    Json(serde_json::json!({ "records": {} }))
}

async fn handle_post_zone(Path(name): Path<String>, Json(zone): Json<kinetic_core::types::DnsZone>) -> Json<serde_json::Value> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    let path = kinetic_core::config::get_zones_dir().join(format!("{}.json", fqdn));
    let _ = std::fs::create_dir_all(kinetic_core::config::get_zones_dir());
    let _ = std::fs::write(path, serde_json::to_string_pretty(&zone).unwrap());
    
    Json(serde_json::json!({ "success": true }))
}

async fn handle_publish_zone(State(_state): State<ApiState>, Path(name): Path<String>) -> Json<serde_json::Value> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    let path = kinetic_core::config::get_zones_dir().join(format!("{}.json", fqdn));
    
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Json(serde_json::json!({ "error": "Zone file not found" }))
    };
    
    let _zone: kinetic_core::types::DnsZone = match serde_json::from_str(&content) {
        Ok(z) => z,
        Err(_) => return Json(serde_json::json!({ "error": "Invalid zone file format" }))
    };
    
    let _keypair = match kinetic_core::types::load_or_create_keypair() {
        Ok(k) => k,
        Err(_) => return Json(serde_json::json!({ "error": "Could not load identity" }))
    };
    
    // We must retrieve the drand pulse info. But this is a generic publish,
    // so we either re-fetch drand, or we just pull the pulse from the stored Commitment?
    // Wait, kinetic_core::types::Reveal requires drand_pulse, drand_randomness, iterations, vdf_proof, salt.
    // If the daemon restarts, it loses those from memory!
    // But they are needed to construct a valid Reveal. 
    // Is Reveal meant to be published every time? Yes. 
    // In that case, we MUST save the initial Reveal parameters locally during registration!
    return Json(serde_json::json!({ "error": "Updating zones dynamically requires persisted registration parameters (not yet implemented)." }));
}
