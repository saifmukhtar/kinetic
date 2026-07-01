use axum::http::{header, Uri};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use kinetic_core::traits::StorageEngine;
use kinetic_core::types::Reveal;
use kinetic_network::NetworkClient;
use kinetic_storage::SledStorage;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{error, info};

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
    pub mempool: Arc<Mutex<kinetic_core::mempool::Mempool>>,
    pub auth_token: String,
    pub dns_handler: Option<kinetic_dns::KineticDnsHandler>,
}

#[derive(Deserialize, Debug)]
pub struct PublishRequest {
    pub reveal: Reveal,
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
            let cache_control = if path == "index.html" {
                "no-cache, no-store, must-revalidate"
            } else {
                "public, max-age=31536000, immutable"
            };
            (
                [
                    (header::CONTENT_TYPE, mime.as_ref()),
                    (header::CACHE_CONTROL, cache_control),
                ],
                content.data,
            )
                .into_response()
        }
        None => {
            // Fallback to index.html for SPA router
            if let Some(content) = WebAssets::get("index.html") {
                let mime = mime_guess::from_path("index.html").first_or_octet_stream();
                (
                    [
                        (header::CONTENT_TYPE, mime.as_ref()),
                        (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
                    ],
                    content.data,
                )
                    .into_response()
            } else {
                (StatusCode::NOT_FOUND, "404 Not Found").into_response()
            }
        }
    }
}

pub fn app(state: ApiState) -> Router {
    use tower_http::cors::{Any, CorsLayer};

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Auth-guarded routes (CLI uses these bare paths with a bearer token)
    let auth_routes = Router::new()
        .route("/commit", post(handle_commit))
        .route("/publish", post(handle_publish))
        .route("/publish-kid", post(handle_publish_kid))
        .route("/publish-manifest", post(handle_publish_manifest))
        .route("/config", axum::routing::get(handle_config))
        .route("/config", axum::routing::post(handle_set_config))
        .route(
            "/vdf/status/{task_id}",
            axum::routing::get(handle_vdf_status),
        )
        .route(
            "/vdf/status/{task_id}",
            axum::routing::delete(handle_vdf_status_delete),
        )
        // .route("/node-stats", axum::routing::get(handle_node_stats))
        .route("/owned-names", axum::routing::get(handle_owned_names))
        .route("/zone/{name}", axum::routing::get(handle_get_zone))
        .route("/zone/{name}", axum::routing::post(handle_post_zone))
        .route(
            "/zone/{name}/publish",
            axum::routing::post(handle_publish_zone),
        )
        .route("/network-status", axum::routing::get(handle_network_status))
        .route("/vdf/register", axum::routing::post(handle_vdf_register))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let public_api_routes = Router::new()
        .route("/resolve/{name}", axum::routing::get(handle_resolve_name))
        .route("/resolve-kid/{did}", axum::routing::get(handle_resolve_kid))
        .route("/delegation", axum::routing::post(handle_delegation))
        .route(
            "/delegation/status/{challenge_hex}",
            axum::routing::get(handle_delegation_status),
        )
        .route("/ws/delegation", axum::routing::get(handle_ws_delegation));

    // Expose all routes under /api (for the UI) and at bare paths (for the CLI).
    // auth_routes is defined with .layer() so the middleware is preserved in both cases.
    Router::new()
        .nest("/api", public_api_routes.clone().merge(auth_routes.clone()))
        .merge(public_api_routes)
        .merge(auth_routes)
        .fallback(get(static_handler))
        .layer(cors)
        .with_state(state)
}

fn generate_and_write_token(token_path: &std::path::Path) -> anyhow::Result<String> {
    let mut token_bytes = [0u8; 32];
    if getrandom::fill(&mut token_bytes).is_err() {
        tracing::error!("Failed to generate secure API token");
    }
    let token = hex::encode(token_bytes);

    if let Some(parent) = token_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(token_path, &token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(token_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(token_path, perms);
        }
    }
    Ok(token)
}

pub async fn start_server(
    network: NetworkClient,
    storage: Arc<SledStorage>,
    port: u16,
    dns_handler: Option<kinetic_dns::KineticDnsHandler>,
    mempool: Arc<Mutex<kinetic_core::mempool::Mempool>>,
) -> anyhow::Result<()> {
    let token_path = kinetic_core::config::get_api_token_path();

    let token = if let Ok(existing) = std::fs::read_to_string(&token_path) {
        let trimmed = existing.trim().to_string();
        if trimmed.len() == 64 {
            trimmed
        } else {
            generate_and_write_token(&token_path)?
        }
    } else {
        generate_and_write_token(&token_path)?
    };

    let state = ApiState {
        network,
        storage,
        vdf_tasks: Arc::new(Mutex::new(HashMap::new())),
        mempool,
        auth_token: token,
        dns_handler,
    };

    // Load persisted mempool state
    if let Ok(Some(data)) = state.storage.get(b"kinetic_mempool_persistence") {
        state
            .mempool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .load(&data);
        tracing::info!("Loaded persisted VDF requests into Mempool");
    }

    // Start background VDF Mempool worker
    start_vdf_worker(state.clone());

    let app = app(state);

    // Case 198: Try binding to IPv4 loopback, fallback to IPv6 loopback
    let listener = match tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(
                "Failed to bind API to 127.0.0.1, trying IPv6 loopback [::1] (Case 198): {}",
                e
            );
            tokio::net::TcpListener::bind(format!("[::1]:{}", port)).await?
        }
    };

    let local_addr = listener.local_addr()?;
    tracing::info!("Starting API server on http://{}", local_addr);
    tracing::info!(
        "Local Daemon API successfully bound and listening on http://{}",
        local_addr
    );

    axum::serve(listener, app).await?;
    Ok(())
}

fn start_vdf_worker(state: ApiState) {
    tokio::spawn(async move {
        tracing::info!("Started background VDF Mempool Worker");
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

            // Pop the highest priority delegation request
            let request_opt = {
                let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
                let req = mempool.pop();
                if req.is_some() {
                    let _ = state
                        .storage
                        .put(b"kinetic_mempool_persistence", &mempool.dump());
                }
                req
            };

            if let Some(req) = request_opt {
                tracing::info!("VDF Worker processing privacy-preserving delegation request...");

                // 1. Fetch Drand challenge to calculate required iterations based on hardware drift
                let drand_client = kinetic_core::drand::DrandClient::new(state.storage.clone());
                let drand_data = match drand_client.fetch_latest().await {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::error!("VDF Worker failed to fetch Drand: {}", e);
                        continue;
                    }
                };

                let challenge = kinetic_core::types::Commitment {
                    hash: req.challenge_hash,
                };
                let required_iters = kinetic_core::consensus_math::ConsensusParams::default()
                    .required_iterations_by_length(req.name_length as usize, drand_data.round);
                let actual_iterations = required_iters;

                let vdf_engine = kinetic_vdf::ChiaVdfEngine::new();
                let challenge_clone = challenge.clone();
                let challenge_hex = hex::encode(req.challenge_hash);

                tracing::info!(
                    "VDF Worker computing VDF for blind challenge {} (iters: {})...",
                    challenge_hex,
                    actual_iterations
                );

                let proof = match tokio::task::spawn_blocking(move || {
                    use kinetic_core::traits::VdfEngine;
                    vdf_engine.evaluate(&challenge_clone, actual_iterations)
                })
                .await
                {
                    Ok(Ok(p)) => p,
                    _ => {
                        tracing::error!("VDF engine failed for challenge {}", challenge_hex);
                        continue;
                    }
                };

                tracing::info!(
                    "VDF Worker successfully computed proof for challenge {}",
                    challenge_hex
                );

                // 3. Save the proof locally so the Mobile app can poll and retrieve it
                let proof_key = format!("kinetic_delegation_proof:{}", challenge_hex);
                let _ = state.storage.put(proof_key.as_bytes(), &proof.proof_bytes);
            }
        }
    });
}

async fn auth_middleware(
    State(state): State<ApiState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token_path = kinetic_core::config::get_api_token_path();
    let expected_token = std::fs::read_to_string(&token_path)
        .unwrap_or_else(|_| state.auth_token.clone())
        .trim()
        .to_string();

    match auth_header {
        Some(header) if header == format!("Bearer {}", expected_token) => Ok(next.run(req).await),
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
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Serialization failed: {}", e),
            ));
        }
    };

    let payload_clone = payload_bytes.clone();

    match state
        .network
        .publish_redundant_payload(&fqdn, payload_bytes)
        .await
    {
        Ok(_) => {
            info!(
                "Successfully queued payload for {} to the DHT network",
                fqdn
            );
            if let Some(dns) = &state.dns_handler {
                dns.invalidate_cache(&fqdn).await;
            }

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
                    info!(
                        "Persisted {} to daemon storage for automatic Heartbeats",
                        fqdn
                    );
                }
            }

            // Persist the full Reveal so zone updates can re-sign without the original VDF params.
            let reveal_key = format!("kinetic_reveal:{}", fqdn);
            if let Ok(reveal_bytes) = serde_json::to_vec(&reveal) {
                let _ = state.storage.put(reveal_key.as_bytes(), &reveal_bytes);
                info!(
                    "Persisted Reveal for {} to daemon storage for future zone updates",
                    fqdn
                );
            }

            // Phase 4.2: Spawn a background task to verify quorum threshold
            let network = state.network.clone();
            let fqdn_clone = fqdn.clone();

            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                match network.verify_quorum(&fqdn_clone, payload_clone).await {
                    Ok(quorum) if quorum >= 3 => {
                        tracing::info!(
                            "Quorum reached for {}: {}/5 nodes confirmed.",
                            fqdn_clone,
                            quorum
                        );
                    }
                    Ok(quorum) => {
                        tracing::warn!(
                            "Quorum failed for {}: only {}/5 nodes confirmed storage.",
                            fqdn_clone,
                            quorum
                        );
                    }
                    Err(e) => tracing::warn!("Quorum check failed for {}: {}", fqdn_clone, e),
                }
            });

            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "Payload accepted and routed to DHT network.".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to publish to DHT: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to publish: {}", e),
            ))
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
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid domain name. You can only commit to apex domains (e.g. 'saif.kin')."
                .to_string(),
        ));
    }

    let payload_bytes = match serde_json::to_vec(&req.commitment) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Serialization failed: {}", e),
            ))
        }
    };

    // The commitment is stored as a special JSON payload (which the network differentiates based on struct parsing)
    // and broadcast to the same 5 derived DHT keys.
    match state
        .network
        .publish_redundant_payload(&fqdn, payload_bytes.clone())
        .await
    {
        Ok(_) => {
            info!(
                "Successfully queued Commitment for {} to the DHT network",
                fqdn
            );

            // Phase 4.2: Spawn a background task to verify quorum threshold
            let network = state.network.clone();
            let fqdn_clone = fqdn.clone();

            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                match network.verify_quorum(&fqdn_clone, payload_bytes).await {
                    Ok(quorum) if quorum >= 3 => tracing::info!(
                        "Quorum reached for commitment of {}: {}/5 nodes confirmed.",
                        fqdn_clone,
                        quorum
                    ),
                    Ok(quorum) => tracing::warn!(
                        "Quorum failed for commitment of {}: only {}/5 nodes confirmed storage.",
                        fqdn_clone,
                        quorum
                    ),
                    Err(e) => tracing::warn!(
                        "Quorum check failed for commitment of {}: {}",
                        fqdn_clone,
                        e
                    ),
                }
            });

            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "Commitment accepted and routed to DHT network.".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to publish Commitment to DHT: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to publish: {}", e),
            ))
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
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Invalid KID signature: {}", e),
        ));
    }

    // 2. Serialize and Publish to DHT
    let payload_bytes = match serde_json::to_vec(&kid) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Serialization failed: {}", e),
            ))
        }
    };
    let fqdn = kid.kid.as_str().to_string(); // Use DID as the DHT key

    match state
        .network
        .publish_redundant_payload(&fqdn, payload_bytes)
        .await
    {
        Ok(_) => {
            info!("Successfully published KID {} to the DHT", fqdn);
            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "KID accepted and routed to DHT".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to publish KID to DHT: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to publish: {}", e),
            ))
        }
    }
}

async fn handle_publish_manifest(
    State(state): State<ApiState>,
    Json(manifest): Json<kinetic_kid::CapabilityManifest>,
) -> Result<Json<PublishResponse>, (StatusCode, String)> {
    let did_str = manifest.kid.as_str();
    info!(
        "Received API publish request for Manifest of KID: {}",
        did_str
    );

    // 1. Resolve the KID Document from DHT to verify against
    let kid_payload = match state.network.resolve_redundant_payload(did_str).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                "KID not found on the network".to_string(),
            ))
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("DHT lookup failed: {}", e),
            ))
        }
    };

    let kid_doc: kinetic_kid::KidDocument = match serde_json::from_slice(&kid_payload) {
        Ok(doc) => doc,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid KID payload on DHT".to_string(),
            ))
        }
    };

    // 2. Verify the manifest against the registered KID
    if let Err(e) = manifest.verify(&kid_doc) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Invalid Manifest signature: {}", e),
        ));
    }

    // 3. Serialize and Publish to DHT under the derived manifest key
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("{}#manifest", did_str).as_bytes());
    let manifest_key = hex::encode(hasher.finalize());

    let payload_bytes = match serde_json::to_vec(&manifest) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Serialization failed: {}", e),
            ))
        }
    };
    match state
        .network
        .publish_redundant_payload(&manifest_key, payload_bytes)
        .await
    {
        Ok(_) => {
            info!("Successfully published Manifest for {} to the DHT", did_str);
            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "Manifest accepted and routed to DHT".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to publish Manifest to DHT: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to publish: {}", e),
            ))
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
                Err(_) => Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid Reveal payload on DHT".to_string(),
                )),
            }
        }
        _ => {
            // Fallback to local storage if DHT lookup fails or returns nothing
            // This rescues users who lost their local reveal.json and the DHT dropped their record
            let reveal_key = format!("kinetic_reveal:{}", fqdn);
            match state.storage.get(reveal_key.as_bytes()) {
                Ok(Some(bytes)) => {
                    match serde_json::from_slice::<kinetic_core::types::Reveal>(&bytes) {
                        Ok(reveal) => {
                            tracing::info!("Recovered {} from local daemon storage backup!", fqdn);
                            Ok(Json(reveal))
                        }
                        Err(_) => Err((
                            StatusCode::NOT_FOUND,
                            format!("Name {} not found on DHT and local backup corrupted", fqdn),
                        )),
                    }
                }
                _ => Err((
                    StatusCode::NOT_FOUND,
                    format!("Name {} not found on DHT or local daemon cache", fqdn),
                )),
            }
        }
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
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("DHT error: {}", e),
            ))
        }
    };

    let kid_doc: kinetic_kid::KidDocument = serde_json::from_slice(&kid_payload).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid KID data".to_string(),
        )
    })?;

    // Try to resolve Manifest
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("{}#manifest", did).as_bytes());
    let manifest_key = hex::encode(hasher.finalize());

    let mut response = serde_json::json!({
        "kid_document": kid_doc,
    });

    if let Ok(Some(man_payload)) = state.network.resolve_redundant_payload(&manifest_key).await {
        if let Ok(manifest) =
            serde_json::from_slice::<kinetic_kid::CapabilityManifest>(&man_payload)
        {
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
        })),
    }
}

async fn handle_set_config(
    State(_state): State<ApiState>,
    Json(payload): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let mut config = kinetic_core::config::KineticConfig::load();
    if let Some(mode) = payload.get("mode").and_then(|m| m.as_str()) {
        config.daemon.network_mode = mode.to_string();
    }
    let _ = config.save();
    Json(
        serde_json::json!({"status": "ok", "message": "Configuration saved. Restart daemon to apply."}),
    )
}

#[derive(Deserialize)]
struct VdfRegisterRequest {
    name: String,
    iterations: Option<u64>,
}

async fn handle_vdf_register(
    State(state): State<ApiState>,
    Json(req): Json<VdfRegisterRequest>,
) -> Json<serde_json::Value> {
    let fqdn = kinetic_core::types::normalize_name(&req.name);
    let task_id = uuid::Uuid::new_v4().to_string();

    // Store initial task state, ensuring only 1 is active
    {
        let mut tasks = state.vdf_tasks.lock().unwrap_or_else(|e| e.into_inner());

        let active_tasks = tasks
            .values()
            .filter(|t| t.progress < 100 && t.error.is_none())
            .count();
        if active_tasks >= 1 {
            return Json(serde_json::json!({
                "error": "A VDF registration is already in progress. Please wait for it to complete."
            }));
        }

        tasks.insert(
            task_id.clone(),
            VdfTaskStatus {
                status: "Initializing".to_string(),
                iterations: req.iterations.unwrap_or(4_194_304), // Default lower for testing in UI
                progress: 0,
                error: None,
            },
        );
    }

    // Spawn blocking background task
    let tasks_clone = state.vdf_tasks.clone();
    let network_clone = state.network.clone();
    let storage_clone = state.storage.clone();
    let task_id_clone = task_id.clone();
    let iterations = req.iterations.unwrap_or(4_194_304);

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
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Keypair error: {}", e),
                );
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
        hasher.update(salt);
        hasher.update(&challenge_bytes);
        hasher.update(pubkey);
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
        if let Err(e) = network_clone
            .publish_redundant_payload(&fqdn, commit_bytes)
            .await
        {
            update_task_error(
                &tasks_clone,
                &task_id_clone,
                format!("DHT Commit Error: {}", e),
            );
            return;
        }

        // Step 3: VDF Evaluation (Blocking)
        update_task_status(
            &tasks_clone,
            &task_id_clone,
            "Computing VDF... (This may take a few minutes)",
            40,
        );
        let required_iters = kinetic_core::consensus_math::ConsensusParams::default()
            .required_iterations(&fqdn, drand_data.round, &pubkey);
        let actual_iterations = std::cmp::max(iterations, required_iters);

        let vdf_engine = kinetic_vdf::ChiaVdfEngine::new();
        let challenge_clone = challenge.clone();

        // Spawn blocking to not starve tokio executor
        let proof = match tokio::task::spawn_blocking(move || {
            use kinetic_core::traits::VdfEngine;
            vdf_engine.evaluate(&challenge_clone, actual_iterations)
        })
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("VDF engine error: {}", e),
                );
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
            vdf_proof: kinetic_core::types::VdfProof {
                proof_bytes: proof.proof_bytes,
            },
            pubkey: pubkey.to_vec(),
            signature: vec![],
        };

        use ed25519_dalek::Signer;
        let signable = reveal.signable_bytes();
        reveal.signature = keypair.sign(&signable).to_bytes().to_vec();

        // Publish to Network
        let reveal_bytes = serde_json::to_vec(&reveal).unwrap();
        if let Err(e) = network_clone
            .publish_redundant_payload(&fqdn, reveal_bytes)
            .await
        {
            update_task_error(
                &tasks_clone,
                &task_id_clone,
                format!("DHT Publish Error: {}", e),
            );
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

fn update_task_status(
    tasks: &Arc<Mutex<HashMap<String, VdfTaskStatus>>>,
    id: &str,
    status: &str,
    progress: u64,
) {
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

async fn handle_vdf_status(
    Path(task_id): Path<String>,
    State(state): State<ApiState>,
) -> Json<serde_json::Value> {
    let task = {
        let tasks = state.vdf_tasks.lock().unwrap_or_else(|e| e.into_inner());
        tasks.get(&task_id).cloned()
    };

    match task {
        Some(t) => Json(serde_json::to_value(t).unwrap()),
        None => Json(serde_json::json!({"error": "Task not found"})),
    }
}

async fn handle_vdf_status_delete(
    Path(task_id): Path<String>,
    State(state): State<ApiState>,
) -> Json<serde_json::Value> {
    let removed = {
        let mut tasks = state.vdf_tasks.lock().unwrap_or_else(|e| e.into_inner());
        tasks.remove(&task_id).is_some()
    };
    Json(serde_json::json!({ "success": removed }))
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

async fn handle_post_zone(
    Path(name): Path<String>,
    Json(zone): Json<kinetic_core::types::DnsZone>,
) -> Json<serde_json::Value> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    let path = kinetic_core::config::get_zones_dir().join(format!("{}.json", fqdn));
    let _ = std::fs::create_dir_all(kinetic_core::config::get_zones_dir());
    let _ = std::fs::write(path, serde_json::to_string_pretty(&zone).unwrap());

    Json(serde_json::json!({ "success": true }))
}

async fn handle_delegation(
    State(state): State<ApiState>,
    Json(req): Json<kinetic_core::types::VdfJobRequest>,
) -> Result<Json<PublishResponse>, (StatusCode, String)> {
    tracing::info!(
        "Received blind VDF Job Request from mobile for length: {}",
        req.name_length
    );

    // Verify name length (must be >= 8 chars)
    if req.name_length < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Delegated name must be at least 8 characters long".to_string(),
        ));
    }

    // Verify Hashcash PoW over the blind challenge hash
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(req.challenge_hash);
    hasher.update(req.hashcash_nonce.to_le_bytes());
    let result = hasher.finalize();

    // Require at least 20 leading zero bits
    let valid_hashcash = result[0] == 0 && result[1] == 0 && (result[2] & 0xF0) == 0;
    if !valid_hashcash {
        return Err((
            StatusCode::BAD_REQUEST,
            "Insufficient Hashcash PoW (requires 20 leading bits)".to_string(),
        ));
    }

    // [Case 106] Prevent Replay Attacks: Check if VDF is already computed
    let challenge_hex = hex::encode(req.challenge_hash);
    let proof_key = format!("kinetic_delegation_proof:{}", challenge_hex);
    if let Ok(Some(_)) = state.storage.get(proof_key.as_bytes()) {
        return Err((
            StatusCode::CONFLICT,
            "Replay attack detected: VDF challenge already processed".to_string(),
        ));
    }

    // Add to Mempool
    let added = {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        let res = mempool.add(req);
        if res {
            let _ = state
                .storage
                .put(b"kinetic_mempool_persistence", &mempool.dump());
        }
        res
    };

    if added {
        Ok(Json(PublishResponse {
            status: "success".to_string(),
            message: "VDF Job request queued in Desktop Mempool".to_string(),
        }))
    } else {
        Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Mempool full, hashcash PoW too low to replace".to_string(),
        ))
    }
}

async fn handle_delegation_status(
    State(state): State<ApiState>,
    Path(challenge_hex): Path<String>,
) -> Json<serde_json::Value> {
    let proof_key = format!("kinetic_delegation_proof:{}", challenge_hex);
    if let Ok(Some(bytes)) = state.storage.get(proof_key.as_bytes()) {
        Json(serde_json::json!({
            "status": "completed",
            "proof_bytes": hex::encode(&bytes)
        }))
    } else {
        Json(serde_json::json!({
            "status": "pending"
        }))
    }
}

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};

async fn handle_ws_delegation(
    ws: WebSocketUpgrade,
    State(state): State<ApiState>,
) -> axum::response::Response {
    ws.on_upgrade(move |socket| process_ws_delegation(socket, state))
}

async fn process_ws_delegation(mut socket: WebSocket, state: ApiState) {
    while let Some(msg) = socket.recv().await {
        if let Ok(Message::Text(text)) = msg {
            if let Ok(req) = serde_json::from_str::<kinetic_core::types::VdfJobRequest>(&text) {
                tracing::info!("Received WebSocket VDF Job Request");

                if req.name_length < 8 {
                    let _ = socket
                        .send(Message::Text(
                            serde_json::to_string(
                                &serde_json::json!({ "error": "Name too short" }),
                            )
                            .unwrap()
                            .into(),
                        ))
                        .await;
                    continue;
                }

                let added = {
                    let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
                    let res = mempool.add(req);
                    if res {
                        let _ = state
                            .storage
                            .put(b"kinetic_mempool_persistence", &mempool.dump());
                    }
                    res
                };

                if added {
                    let _ = socket
                        .send(Message::Text(
                            serde_json::to_string(&serde_json::json!({ "status": "queued" }))
                                .unwrap()
                                .into(),
                        ))
                        .await;
                } else {
                    let _ = socket
                        .send(Message::Text(
                            serde_json::to_string(&serde_json::json!({ "error": "Mempool full" }))
                                .unwrap()
                                .into(),
                        ))
                        .await;
                }
            }
        }
    }
}

async fn handle_publish_zone(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    let fqdn = kinetic_core::types::normalize_name(&name);

    // 1. Read the current zone file
    let zone_path = kinetic_core::config::get_zones_dir().join(format!("{}.json", fqdn));
    let content = match std::fs::read_to_string(&zone_path) {
        Ok(c) => c,
        Err(_) => {
            return Json(
                serde_json::json!({ "error": "Zone file not found. Save your zone first via POST /zone/{name}." }),
            )
        }
    };
    let zone: kinetic_core::types::DnsZone = match serde_json::from_str(&content) {
        Ok(z) => z,
        Err(_) => return Json(serde_json::json!({ "error": "Invalid zone file format" })),
    };

    // 2. Load the persisted Reveal (stored at registration time)
    let reveal_key = format!("kinetic_reveal:{}", fqdn);
    let reveal_bytes = match state.storage.get(reveal_key.as_bytes()) {
        Ok(Some(b)) => b,
        _ => {
            return Json(
                serde_json::json!({ "error": "No registration record found for this name. Register the name first." }),
            )
        }
    };
    let mut reveal: kinetic_core::types::Reveal = match serde_json::from_slice(&reveal_bytes) {
        Ok(r) => r,
        Err(_) => {
            return Json(serde_json::json!({ "error": "Stored registration data is corrupted." }))
        }
    };

    // 3. Load the daemon keypair and re-sign with the updated payload
    let keypair = match kinetic_core::types::load_or_create_keypair() {
        Ok(k) => k,
        Err(_) => return Json(serde_json::json!({ "error": "Could not load identity keypair." })),
    };
    reveal.payload = serde_json::to_vec(&zone).unwrap_or_default();
    let signable = reveal.signable_bytes();
    use ed25519_dalek::Signer;
    reveal.signature = keypair.sign(&signable).to_bytes().to_vec();

    // 4. Update the stored Reveal so future zone publishes reflect the latest payload
    if let Ok(updated_bytes) = serde_json::to_vec(&reveal) {
        let _ = state.storage.put(reveal_key.as_bytes(), &updated_bytes);
    }

    // 5. Serialize and publish to the DHT
    let dht_payload = match serde_json::to_vec(&reveal) {
        Ok(b) => b,
        Err(e) => {
            return Json(serde_json::json!({ "error": format!("Serialization error: {}", e) }))
        }
    };
    match state
        .network
        .publish_redundant_payload(&fqdn, dht_payload)
        .await
    {
        Ok(_) => {
            info!("Zone published to DHT for {}", fqdn);
            if let Some(dns) = &state.dns_handler {
                dns.invalidate_cache(&fqdn).await;
            }
            Json(
                serde_json::json!({ "success": true, "message": "Zone published to the Kinetic DHT network." }),
            )
        }
        Err(e) => Json(serde_json::json!({ "error": format!("DHT publish failed: {}", e) })),
    }
}
