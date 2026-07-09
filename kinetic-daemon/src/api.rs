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
    pub vdf_semaphore: Arc<tokio::sync::Semaphore>,
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
        .route("/vdf/status/{task_id}", axum::routing::get(handle_vdf_status))
        .route("/vdf/status/{task_id}", axum::routing::delete(handle_vdf_status_delete))
        .route("/owned-names", axum::routing::get(handle_owned_names))
        .route("/zone/{name}", axum::routing::post(handle_post_zone))
        .route("/zone/{name}/publish", axum::routing::post(handle_publish_zone))
        .route("/vdf/register", axum::routing::post(handle_vdf_register))
        .route("/vdf/renew", axum::routing::post(handle_vdf_renew))
        .route("/delegation", axum::routing::post(handle_delegation))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let public_api_routes = Router::new()
        .route("/network-status", axum::routing::get(handle_network_status))
        .route("/zone/{name}", axum::routing::get(handle_get_zone))
        .route("/resolve/{name}", axum::routing::get(handle_resolve_name))
        .route("/resolve-kid/{did}", axum::routing::get(handle_resolve_kid))
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
        .layer(cors)
        .with_state(state)
}

fn generate_and_write_token(token_path: &std::path::Path) -> anyhow::Result<String> {
    let mut token_bytes = [0u8; 32];
    getrandom::fill(&mut token_bytes).map_err(|e| {
        tracing::error!(
            error_code = "KIN-IMPL-001",
            severity = "Critical",
            "FATAL: getrandom failed — cannot generate secure API token. Refusing to start with a predictable token. Error: {}",
            e
        );
        anyhow::anyhow!("[KIN-IMPL-001] getrandom failed: {}. Cannot generate a secure API token.", e)
    })?;
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
        vdf_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
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

    let mut listener = None;
    for _ in 0..10 {
        if let Ok(l) = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await {
            listener = Some(l);
            break;
        } else if let Ok(l) = tokio::net::TcpListener::bind(format!("[::1]:{}", port)).await {
            tracing::warn!("Failed to bind API to 127.0.0.1, successfully bound to IPv6 loopback [::1] (Case 198)");
            listener = Some(l);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let listener = listener.ok_or_else(|| {
        anyhow::anyhow!("Failed to bind API to 127.0.0.1 or [::1] on port {}", port)
    })?;

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
                let drand_client =
                    kinetic_core::drand::DrandClient::new(Some(state.storage.clone()));
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

                let permit = match state.vdf_semaphore.acquire().await {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::error!("VDF Semaphore closed. Worker exiting.");
                        return;
                    }
                };

                let proof = match tokio::task::spawn_blocking(move || {
                    use kinetic_core::traits::VdfEngine;
                    vdf_engine.evaluate(&challenge_clone, actual_iterations)
                })
                .await
                {
                    Ok(Ok(p)) => p,
                    Ok(Err(e)) => {
                        tracing::error!(error_code = "KIN-VDF-002", error = ?e, "VDF engine returned error for challenge {}", challenge_hex);
                        continue;
                    }
                    Err(e) => {
                        tracing::error!(error_code = "KIN-VDF-002", error = ?e, "VDF worker task panicked for challenge {}", challenge_hex);
                        continue;
                    }
                };

                drop(permit);

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
    let expected_token = match std::fs::read_to_string(&token_path) {
        Ok(t) => t.trim().to_string(),
        Err(e) => {
            tracing::warn!(error_code="KIN-IMPL-004", error=?e, "Could not read token file {:?}, falling back to in-memory token", token_path);
            state.auth_token.clone()
        }
    };

    match auth_header {
        Some(header) if header == format!("Bearer {}", expected_token) => Ok(next.run(req).await),
        _ => {
            tracing::warn!(
                "Rejecting unauthorized API request. Expected token length: {}, Header: {:?}",
                expected_token.len(),
                auth_header
            );
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

async fn handle_publish(
    State(state): State<ApiState>,
    Json(req): Json<PublishRequest>,
) -> Result<Json<PublishResponse>, (StatusCode, Json<serde_json::Value>)> {
    info!("Received API publish request for name: {}", req.reveal.name);

    // Normalize to canonical format
    let fqdn = kinetic_core::types::normalize_name(&req.reveal.name);
    if !kinetic_core::types::is_valid_apex_name(&fqdn) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "Invalid domain name. You can only register apex domains (e.g. 'saif.kin'). Subdomains are strictly routed dynamically at the DNS/Proxy level."}),
            ),
        ));
    }
    // Ensure the Reveal internally matches the normalized name exactly
    let mut reveal = req.reveal;
    reveal.name = fqdn.clone();

    // Finding 4 (High): Run the structural validator before touching the network.
    // Catches bad protocol versions and oversized payloads at the gate.
    if let Err(e) = reveal.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid Reveal: {}", e)})),
        ));
    }

    // Finding 4 (High): Enforce drand staleness — reject Reveals whose VDF pulse is older
    // than RESQUARING_EPOCH_ROUNDS. Fetch the current beacon round, falling back to the
    // sled-cached value so offline-first nodes aren’t broken.
    let current_round: u64 = {
        let drand_client = kinetic_core::drand::DrandClient::new(Some(state.storage.clone()));
        match drand_client.fetch_latest().await {
            Ok(pulse) => pulse.round,
            Err(_) => {
                // Graceful fallback: read the last known round from sled.
                // If even that is unavailable, we allow the publish to proceed —
                // the DHT store layer will still enforce its own staleness check.
                tracing::warn!(
                    error_code = "KIN-API-001",
                    "handle_publish: Could not fetch live drand round, \
                     falling back to cached value for staleness check"
                );
                state
                    .storage
                    .get(b"kinetic_last_drand_round")
                    .ok()
                    .flatten()
                    .and_then(|b| {
                        b.get(..8)
                            .map(|s| u64::from_be_bytes(s.try_into().unwrap_or([0; 8])))
                    })
                    .unwrap_or(0)
            }
        }
    };

    if current_round > 0 {
        let age = current_round.saturating_sub(reveal.drand_pulse);
        if age > kinetic_core::types::RESQUARING_EPOCH_ROUNDS {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!(
                        "Reveal rejected: VDF pulse {} is {} rounds old (max allowed: {}). \
                         Please re-compute a fresh VDF proof.",
                        reveal.drand_pulse,
                        age,
                        kinetic_core::types::RESQUARING_EPOCH_ROUNDS
                    )
                })),
            ));
        }
    }

    let payload_bytes = match serde_json::to_vec(&reveal) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Serialization failed: {}", e)})),
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

            // Persist the owned name to embedded storage so the Heartbeat loop can maintain it
            let owned_key = b"kinetic_owned_names";
            let mut owned_names: Vec<String> = match state.storage.get(owned_key) {
                Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(error_code="KIN-IMPL-003", error=?e, "Corrupted data in Sled storage for owned_names key");
                        Vec::new()
                    }
                },
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
            tracing::error!("Failed to publish to DHT: {}", e);
            let api_err = kinetic_core::ApiError::from(e);
            Err((
                StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(serde_json::to_value(api_err).unwrap_or_default()),
            ))
        }
    }
}

async fn handle_commit(
    State(state): State<ApiState>,
    Json(req): Json<kinetic_core::types::CommitRequest>,
) -> Result<Json<PublishResponse>, (StatusCode, Json<serde_json::Value>)> {
    info!("Received API commit request for name: {}", req.name);

    // Normalize to canonical format
    let fqdn = kinetic_core::types::normalize_name(&req.name);
    if !kinetic_core::types::is_valid_apex_name(&fqdn) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "Invalid domain name. You can only commit to apex domains (e.g. 'saif.kin')."}),
            ),
        ));
    }

    // Finding 1 (Medium): Reject null/all-zero commitment hashes.
    // An all-zero hash is a trivial commitment that binds to nothing — any reveal whose
    // hash also produces zeros would match it, creating a commitment without any
    // cryptographic binding to the actual name or salt.
    if req.commitment.hash == [0u8; 32] {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Commitment hash must not be all-zeros. \
                          Please provide a valid cryptographic commitment."
            })),
        ));
    }

    let payload_bytes = match serde_json::to_vec(&req.commitment) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Serialization failed: {}", e)})),
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
            tracing::error!("Failed to publish Commitment to DHT: {}", e);
            let api_err = kinetic_core::ApiError::from(e);
            Err((
                StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(serde_json::to_value(api_err).unwrap_or_default()),
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
        Ok(p) => p,
        Err(e) => {
            let status = match e {
                kinetic_core::error::ResolutionError::NotFound { .. } => StatusCode::NOT_FOUND,
                kinetic_core::error::ResolutionError::Offline => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return Err((status, format!("DHT lookup failed: {}", e)));
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
) -> Result<Json<kinetic_core::types::Reveal>, (StatusCode, Json<serde_json::Value>)> {
    let fqdn = kinetic_core::types::normalize_name(&name);

    match state.network.resolve_redundant_payload(&fqdn).await {
        Ok(payload) => match serde_json::from_slice::<kinetic_core::types::Reveal>(&payload) {
            Ok(reveal) => Ok(Json(reveal)),
            Err(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Invalid Reveal payload on DHT"})),
            )),
        },
        Err(kinetic_core::error::ResolutionError::NotFound { .. }) => {
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
                            Json(
                                serde_json::json!({"error": format!("Name {} not found on DHT and local backup corrupted", fqdn)}),
                            ),
                        )),
                    }
                }
                _ => Err((
                    StatusCode::NOT_FOUND,
                    Json(
                        serde_json::json!({"error": format!("Name {} not found on DHT or local daemon cache", fqdn)}),
                    ),
                )),
            }
        }
        Err(kinetic_core::error::ResolutionError::Offline) => {
            let api_err =
                kinetic_core::ApiError::from(kinetic_core::error::ResolutionError::Offline);
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::to_value(api_err).unwrap_or_default()),
            ))
        }
        Err(e) => {
            let api_err = kinetic_core::ApiError::from(e);
            tracing::warn!(
                error_code = api_err.code,
                "Resolution error: {}",
                api_err.detail
            );
            Err((
                StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(serde_json::to_value(api_err).unwrap_or_default()),
            ))
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
        Ok(p) => p,
        Err(e) => {
            let status = match &e {
                kinetic_core::error::ResolutionError::NotFound { .. } => StatusCode::NOT_FOUND,
                kinetic_core::error::ResolutionError::Offline => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return Err((status, format!("DHT error: {}", e)));
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

    if let Ok(man_payload) = state.network.resolve_redundant_payload(&manifest_key).await {
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
        Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error_code="KIN-IMPL-003", error=?e, "Corrupted data in Sled storage for owned_names key");
                Vec::new()
            }
        },
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
pub struct NameRegisterRequest {
    pub name: String,
    pub iterations: Option<u64>,
}

#[derive(Deserialize)]
pub struct NameRenewRequest {
    pub name: String,
    pub iterations: Option<u64>,
}

#[derive(Deserialize)]
struct VdfRegisterRequest {
    name: String,
    iterations: Option<u64>,
}

async fn handle_vdf_register(
    State(state): State<ApiState>,
    Json(req): Json<VdfRegisterRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
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
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "A VDF registration is already in progress. Please wait for it to complete."
                })),
            ));
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
        let drand_client = kinetic_core::drand::DrandClient::new(Some(storage_clone.clone()));
        let drand_data = match drand_client.fetch_latest().await {
            Ok(d) => d,
            Err(e) => {
                update_task_error(&tasks_clone, &task_id_clone, format!("Drand error: {}", e));
                return;
            }
        };

        // Step 2: Commitment
        update_task_status(&tasks_clone, &task_id_clone, "Generating Commitment", 20);
        let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
        let keypair = match kinetic_core::types::load_keypair(&identity_path.to_string_lossy()) {
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
        getrandom::fill(&mut salt).unwrap_or_default();
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
        let commit_bytes = match serde_json::to_vec(&challenge) {
            Ok(b) => b,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Serialization failed in VDF task: {}", e),
                );
                tracing::error!(
                    error_code = "KIN-VDF-002",
                    "Serialization failed in VDF task: {}",
                    e
                );
                return;
            }
        };
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

        let permit_res = state.vdf_semaphore.clone().acquire_owned().await;
        if permit_res.is_err() {
            update_task_error(&tasks_clone, &task_id_clone, "VDF Semaphore closed".into());
            return;
        }
        let permit = permit_res.unwrap();

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

        drop(permit);

        update_task_status(&tasks_clone, &task_id_clone, "Publishing Registration", 90);

        // Construct Reveal
        let records = HashMap::new();
        let zone = kinetic_core::types::DnsZone { records };
        let payload = match serde_json::to_vec(&zone) {
            Ok(b) => b,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Serialization failed in VDF task: {}", e),
                );
                tracing::error!(
                    error_code = "KIN-VDF-002",
                    "Serialization failed in VDF task: {}",
                    e
                );
                return;
            }
        };

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
            previous_proof: None,
            miner_pubkey: None,
            points_spent: None,
        };

        use ed25519_dalek::Signer;
        let signable = reveal.signable_bytes();
        reveal.signature = keypair.sign(&signable).to_bytes().to_vec();

        // Publish to Network
        let reveal_bytes = match serde_json::to_vec(&reveal) {
            Ok(b) => b,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Serialization failed in VDF task: {}", e),
                );
                tracing::error!(
                    error_code = "KIN-VDF-002",
                    "Serialization failed in VDF task: {}",
                    e
                );
                return;
            }
        };
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
            if let Ok(b) = serde_json::to_vec(&owned) {
                let _ = storage_clone.put(b"kinetic_owned_names", &b);
            }
        }

        // Save default zone file
        let zones_dir = kinetic_core::config::get_zones_dir();
        let _ = std::fs::create_dir_all(&zones_dir);
        let path = zones_dir.join(format!("{}.json", fqdn));
        if let Ok(s) = serde_json::to_string_pretty(&zone) {
            if let Err(e) = std::fs::write(&path, s) {
                tracing::warn!(
                    error_code = "KIN-IMPL-005",
                    "Failed to write zone file: {}",
                    e
                );
            }
        }

        update_task_status(&tasks_clone, &task_id_clone, "Complete", 100);
    });

    Ok(Json(serde_json::json!({
        "task_id": task_id,
        "message": "VDF generation started"
    })))
}

pub async fn handle_vdf_renew(
    State(state): State<ApiState>,
    Json(req): Json<NameRenewRequest>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    let fqdn = kinetic_core::types::normalize_name(&req.name);
    let mut tasks = state.vdf_tasks.lock().unwrap();

    // In ApiState there is no vdf_events yet, so we just check for conflicts by looking at the tasks map directly.
    for (id, task) in tasks.iter() {
        if task.status != "Complete" && task.status != "Failed" {
            // Since we can't easily check name if it's not in VdfTaskStatus, we skip conflict checks for now,
            // or we could inspect the current tasks, but we'll just allow it since the CLI does too.
        }
    }

    let task_id = uuid::Uuid::new_v4().to_string();
    let initial_task = VdfTaskStatus {
        status: "Starting Renewal...".into(),
        progress: 0,
        error: None,
        iterations: req.iterations.unwrap_or(4_194_304),
    };
    tasks.insert(task_id.clone(), initial_task.clone());
    drop(tasks);

    let tasks_clone = state.vdf_tasks.clone();
    let network_clone = state.network.clone();
    let storage_clone = state.storage.clone();
    let task_id_clone = task_id.clone();
    let iterations = req.iterations.unwrap_or(4_194_304);

    tokio::spawn(async move {
        // Step 1: Read previous Reveal from Sled storage
        update_task_status(&tasks_clone, &task_id_clone, "Loading previous reveal", 5);
        let local_reveal_key = format!("kinetic_reveal:{}", fqdn);
        let old_reveal_bytes = match storage_clone.get(local_reveal_key.as_bytes()) {
            Ok(Some(b)) => b,
            _ => {
                update_task_error(&tasks_clone, &task_id_clone, format!("Domain {} not found locally", fqdn));
                return;
            }
        };
        let old_reveal: kinetic_core::types::Reveal = match serde_json::from_slice(&old_reveal_bytes) {
            Ok(r) => r,
            Err(e) => {
                update_task_error(&tasks_clone, &task_id_clone, format!("Failed to parse old reveal: {}", e));
                return;
            }
        };

        // Step 2: Drand
        update_task_status(&tasks_clone, &task_id_clone, "Fetching Drand beacon", 10);
        let drand_client = kinetic_core::drand::DrandClient::new(Some(storage_clone.clone()));
        let drand_data = match drand_client.fetch_latest().await {
            Ok(d) => d,
            Err(e) => {
                update_task_error(&tasks_clone, &task_id_clone, format!("Drand error: {}", e));
                return;
            }
        };

        // Step 3: Commitment
        update_task_status(&tasks_clone, &task_id_clone, "Generating Commitment", 20);
        let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
        let keypair = match kinetic_core::types::load_keypair(&identity_path.to_string_lossy()) {
            Ok(k) => k,
            Err(e) => {
                update_task_error(&tasks_clone, &task_id_clone, format!("Keypair error: {}", e));
                return;
            }
        };
        let pubkey = keypair.verifying_key().to_bytes();
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt).unwrap_or_default();
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

        update_task_status(&tasks_clone, &task_id_clone, "Broadcasting Commitment", 30);
        let commit_bytes = match serde_json::to_vec(&challenge) {
            Ok(b) => b,
            Err(e) => {
                update_task_error(&tasks_clone, &task_id_clone, format!("Serialization failed in VDF task: {}", e));
                return;
            }
        };
        if let Err(e) = network_clone.publish_redundant_payload(&fqdn, commit_bytes).await {
            update_task_error(&tasks_clone, &task_id_clone, format!("DHT Commit Error: {}", e));
            return;
        }

        // Step 4: VDF Evaluation (Blocking)
        update_task_status(&tasks_clone, &task_id_clone, "Computing Renewal VDF... (This may take a few minutes)", 40);
        
        let required_iters = kinetic_core::consensus_math::ConsensusParams::default()
            .required_iterations(&fqdn, drand_data.round, &pubkey);
        // Renewals get an 80% discount
        let discounted_iters = (required_iters as f64 * 0.2) as u64;
        let actual_iterations = std::cmp::max(iterations, discounted_iters);

        let vdf_engine = kinetic_vdf::ChiaVdfEngine::new();
        let challenge_clone = challenge.clone();

        let permit_res = state.vdf_semaphore.clone().acquire_owned().await;
        if permit_res.is_err() {
            update_task_error(&tasks_clone, &task_id_clone, "VDF Semaphore closed".into());
            return;
        }
        let permit = permit_res.unwrap();

        let proof = match tokio::task::spawn_blocking(move || {
            use kinetic_core::traits::VdfEngine;
            vdf_engine.evaluate(&challenge_clone, actual_iterations)
        })
        .await
        {
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

        drop(permit);

        update_task_status(&tasks_clone, &task_id_clone, "Publishing Renewal", 90);

        let previous_proof = kinetic_core::types::PreviousProof {
            salt: old_reveal.salt,
            drand_pulse: old_reveal.drand_pulse,
            drand_randomness: old_reveal.drand_randomness.clone(),
            iterations: old_reveal.iterations,
            vdf_proof: old_reveal.vdf_proof.clone(),
            signature: old_reveal.signature.clone(),
        };

        let mut new_reveal = kinetic_core::types::Reveal {
            protocol_version: 2,
            name: fqdn.clone(),
            payload: old_reveal.payload.clone(), // Keep existing zone payload
            salt,
            drand_pulse: drand_data.round,
            drand_randomness: drand_data.randomness.clone(),
            iterations: actual_iterations,
            vdf_proof: kinetic_core::types::VdfProof {
                proof_bytes: proof.proof_bytes,
            },
            pubkey: pubkey.to_vec(),
            signature: vec![],
            previous_proof: Some(previous_proof),
            miner_pubkey: None,
            points_spent: None,
        };

        use ed25519_dalek::Signer;
        let signable = new_reveal.signable_bytes();
        new_reveal.signature = keypair.sign(&signable).to_bytes().to_vec();

        let reveal_bytes = match serde_json::to_vec(&new_reveal) {
            Ok(b) => b,
            Err(e) => {
                update_task_error(&tasks_clone, &task_id_clone, format!("Serialization failed in VDF task: {}", e));
                return;
            }
        };
        if let Err(e) = network_clone.publish_redundant_payload(&fqdn, reveal_bytes.clone()).await {
            update_task_error(&tasks_clone, &task_id_clone, format!("DHT Publish Error: {}", e));
            return;
        }

        let local_reveal_key = format!("kinetic_reveal:{}", fqdn);
        let _ = storage_clone.put(local_reveal_key.as_bytes(), &reveal_bytes);

        update_task_status(&tasks_clone, &task_id_clone, "Complete", 100);
    });

    Ok(Json(serde_json::json!({
        "task_id": task_id,
        "message": "Renewal VDF generation started"
    })))
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
        Some(t) => Json(serde_json::to_value(t).unwrap_or_default()),
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

async fn handle_get_zone(
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    let path = kinetic_core::config::get_zones_dir().join(format!("{}.json", fqdn));
    if let Ok(content) = std::fs::read_to_string(path) {
        match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(zone) => return Ok(Json(zone)),
            Err(e) => {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(
                        serde_json::json!({ "error": format!("Invalid zone file format: {}", e) }),
                    ),
                ))
            }
        }
    }
    Err((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "Zone not found" })),
    ))
}

async fn handle_post_zone(
    Path(name): Path<String>,
    Json(zone): Json<kinetic_core::types::DnsZone>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    let path = kinetic_core::config::get_zones_dir().join(format!("{}.json", fqdn));
    let _ = std::fs::create_dir_all(kinetic_core::config::get_zones_dir());

    let content = match serde_json::to_string_pretty(&zone) {
        Ok(c) => c,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Serialization failed: {}", e) })),
            ))
        }
    };
    if let Err(e) = std::fs::write(&path, content) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("File write failed: {}", e) })),
        ));
    }

    Ok(Json(serde_json::json!({ "success": true })))
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
                            .unwrap_or_default()
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
                                .unwrap_or_default()
                                .into(),
                        ))
                        .await;
                } else {
                    let _ = socket
                        .send(Message::Text(
                            serde_json::to_string(&serde_json::json!({ "error": "Mempool full" }))
                                .unwrap_or_default()
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
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let fqdn = kinetic_core::types::normalize_name(&name);

    // 1. Read the current zone file
    let zone_path = kinetic_core::config::get_zones_dir().join(format!("{}.json", fqdn));
    let content = match std::fs::read_to_string(&zone_path) {
        Ok(c) => c,
        Err(_) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(
                    serde_json::json!({ "error": "Zone file not found. Save your zone first via POST /zone/{name}." }),
                ),
            ))
        }
    };
    let zone: kinetic_core::types::DnsZone = match serde_json::from_str(&content) {
        Ok(z) => z,
        Err(_) => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "error": "Invalid zone file format" })),
            ))
        }
    };

    // 2. Load the persisted Reveal (stored at registration time)
    let reveal_key = format!("kinetic_reveal:{}", fqdn);
    let reveal_bytes = match state.storage.get(reveal_key.as_bytes()) {
        Ok(Some(b)) => b,
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(
                    serde_json::json!({ "error": "No registration record found for this name. Register the name first." }),
                ),
            ))
        }
    };
    let mut reveal: kinetic_core::types::Reveal = match serde_json::from_slice(&reveal_bytes) {
        Ok(r) => r,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Stored registration data is corrupted." })),
            ))
        }
    };

    // 3. Load the daemon keypair and re-sign with the updated payload
    let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
    let keypair = match kinetic_core::types::load_keypair(&identity_path.to_string_lossy()) {
        Ok(k) => k,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Could not load identity keypair." })),
            ))
        }
    };

    reveal.payload = match serde_json::to_vec(&zone) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error_code="KIN-VDF-002", error=?e, "Failed to serialize zone payload — cannot publish");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "[KIN-VDF-002] Failed to serialize zone data" })),
            ));
        }
    };

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
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Serialization error: {}", e) })),
            ))
        }
    };
    match state
        .network
        .publish_redundant_payload(&fqdn, dht_payload)
        .await
    {
        Ok(_) => {
            tracing::info!("Zone published to DHT for {}", fqdn);
            Ok(Json(
                serde_json::json!({ "success": true, "message": "Zone published to the Kinetic DHT network." }),
            ))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({ "error": format!("DHT publish failed: {}", e.user_message()) }),
            ),
        )),
    }
}
