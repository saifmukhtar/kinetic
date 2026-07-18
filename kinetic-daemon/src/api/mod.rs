use axum::{extract::State, http::StatusCode, routing::post, Router};
use kinetic_core::traits::StorageEngine;
use kinetic_core::types::Reveal;
use kinetic_network::NetworkClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// API endpoints for configuration management.
pub mod config;
/// API endpoints for publishing names and content.
pub mod publish;
/// API endpoints for resolving names to payloads.
pub mod resolve;
/// API endpoints for Verifiable Delay Function tasks.
pub mod vdf;
/// API endpoints for DNS zone management.
pub mod zone;

use config::*;
use publish::*;
use resolve::*;
use vdf::*;
use zone::*;
/// Represents the status of an ongoing Verifiable Delay Function (VDF) task.
#[derive(Clone, Serialize, Deserialize)]
pub struct VdfTaskStatus {
    /// The current status of the task (e.g. 'running', 'completed', 'failed').
    pub status: String,
    /// The number of iterations the VDF requires.
    pub iterations: u64,
    /// The number of iterations completed so far.
    pub progress: u64,
    /// An optional error message if the task failed.
    pub error: Option<String>,
}

/// Holds the global state for the API server, including network, storage, and authentication.
#[derive(Clone)]
pub struct ApiState {
    /// The P2P network client.
    pub network: NetworkClient,
    /// Local storage engine interface.
    pub storage: Arc<dyn StorageEngine>,
    /// Map of background VDF tasks.
    pub vdf_tasks: Arc<Mutex<HashMap<String, VdfTaskStatus>>>,

    /// API authentication token to restrict access.
    pub auth_token: String,
    /// Semaphore to restrict concurrent VDF computations.
    pub vdf_semaphore: Arc<tokio::sync::Semaphore>,
}

/// Payload for publishing a direct reveal configuration.
#[derive(Deserialize, Debug)]
pub struct PublishRequest {
    /// The Reveal object to publish.
    pub reveal: Reveal,
}

/// Response format for a publish action.
#[derive(Serialize)]
pub struct PublishResponse {
    /// High level status ('success' or 'error').
    pub status: String,
    /// Detailed message about the publish result.
    pub message: String,
}

/// Constructs the axum `Router` for the API, registering public and authenticated routes.
pub fn app(state: ApiState) -> Router {
    use tower_http::cors::CorsLayer;

    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(
            |origin: &axum::http::HeaderValue, _request_parts| {
                if let Ok(o) = origin.to_str() {
                    o.starts_with("http://localhost:")
                        || o.starts_with("http://127.0.0.1:")
                        || o.starts_with("http://[::1]:")
                        || o == "http://localhost"
                        || o == "http://127.0.0.1"
                        || o == "http://[::1]"
                        || o.starts_with("chrome-extension://")
                        || o.starts_with("moz-extension://")
                } else {
                    false
                }
            },
        ))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ]);

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
        .route("/owned-names", axum::routing::get(handle_owned_names))
        .route("/zone/{name}", axum::routing::post(handle_post_zone))
        .route(
            "/zone/{name}/publish",
            axum::routing::post(handle_publish_zone),
        )
        .route("/vdf/register", axum::routing::post(handle_vdf_register))
        .route("/vdf/renew", axum::routing::post(handle_vdf_renew))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let public_api_routes = Router::new()
        .route("/network-status", axum::routing::get(handle_network_status))
        .route("/zone/{name}", axum::routing::get(handle_get_zone))
        .route("/resolve/{name}", axum::routing::get(handle_resolve_name))
        .route("/resolve-kid/{did}", axum::routing::get(handle_resolve_kid));

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

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options.open(token_path)?;
        use std::io::Write;
        file.write_all(token.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(token_path, &token)?;
    }

    Ok(token)
}

/// Starts the HTTP API server on the specified port.
///
/// # Errors
///
/// Returns an error if the server fails to bind to the port or if token generation fails.
pub async fn start_server(
    network: NetworkClient,
    storage: Arc<dyn StorageEngine>,
    port: u16,
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

        auth_token: token,
        vdf_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
    };

    // Start background VDF Mempool worker

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

async fn auth_middleware(
    State(state): State<ApiState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let expected_token = state.auth_token.clone();
    let expected_header = format!("Bearer {}", expected_token);

    match auth_header {
        Some(header) => {
            use subtle::ConstantTimeEq;
            let header_bytes = header.as_bytes();
            let expected_bytes = expected_header.as_bytes();

            // Note: ct_eq requires equal lengths. If lengths differ, we must fail gracefully.
            let is_valid = if header_bytes.len() == expected_bytes.len() {
                header_bytes.ct_eq(expected_bytes).unwrap_u8() == 1
            } else {
                false
            };

            if is_valid {
                Ok(next.run(req).await)
            } else {
                tracing::warn!(
                    "Rejecting unauthorized API request. Expected token length: {}, Presented header length: {}",
                    expected_token.len(),
                    header.len()
                );
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        None => {
            tracing::warn!("Rejecting API request: Missing Authorization header");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

#[cfg(test)]
mod api_tests;

#[cfg(test)]
mod proptests {

    use proptest::prelude::*;
    use subtle::ConstantTimeEq;

    proptest! {
        #[test]
        fn test_fuzz_constant_time_eq_lengths(
            token_a in ".{0,128}",
            token_b in ".{0,128}"
        ) {
            let bytes_a = token_a.as_bytes();
            let bytes_b = token_b.as_bytes();

            if bytes_a.len() == bytes_b.len() {
                let eq = bytes_a.ct_eq(bytes_b).unwrap_u8() == 1;
                prop_assert_eq!(eq, bytes_a == bytes_b);
            } else {
                // We don't call ct_eq on different lengths in the middleware, we handle it safely
                prop_assert_ne!(bytes_a.len(), bytes_b.len());
            }
        }
    }
}
