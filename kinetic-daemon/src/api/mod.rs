//! HTTP REST API router, authentication middleware, state management, and server bootstrap.

use axum::{Router, extract::State, http::StatusCode, routing::post};
use kinetic_core::traits::StorageEngine;

use kinetic_network::NetworkClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// API endpoints for Atlas NSP sync.
pub mod atlas;
/// API endpoints for configuration management.
pub mod config;
/// Error mappings and Newtype wrappers for HTTP response conversion.
pub mod error;
/// API endpoints for streaming Gossip.
pub mod gossip;
/// API endpoints for KID local management.
pub mod kid;
/// API endpoints for publishing names and content.
pub mod publish;
/// API endpoints for resolving names to payloads.
pub mod resolve;
/// API endpoints for streaming Kinetic time.
pub mod time;
/// API endpoints for Verifiable Delay Function tasks.
pub mod vdf;
/// API endpoints for DNS zone management.
pub mod zone;

use atlas::*;
use config::*;
use gossip::*;
use kid::*;
use publish::*;
use resolve::*;
use time::*;
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

/// The access role granted by the provided token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Full administrator access.
    Admin,
    /// Permission to publish zones.
    Publish,
    /// Permission to register/renew VDF proofs.
    Vdf,
    /// Permission to participate in governance.
    Governance,
    /// Permission for the Atlas bridge.
    Atlas,
}

impl Role {
    /// Returns whether this role can publish records.
    pub fn can_publish(&self) -> bool {
        matches!(self, Role::Admin | Role::Publish)
    }
    /// Returns whether this role can perform VDF operations.
    pub fn can_vdf(&self) -> bool {
        matches!(self, Role::Admin | Role::Vdf)
    }
    /// Returns whether this role can trigger governance updates.
    pub fn can_govern(&self) -> bool {
        matches!(self, Role::Admin | Role::Governance)
    }
    /// Returns whether this role is a full administrator.
    pub fn is_admin(&self) -> bool {
        matches!(self, Role::Admin)
    }
}

/// The set of generated scoped API tokens for this daemon.
#[derive(Clone)]
pub struct ApiTokens {
    /// The admin token.
    pub admin: String,
    /// The publish token.
    pub publish: String,
    /// The VDF token.
    pub vdf: String,
    /// The governance token.
    pub governance: String,
    /// The atlas token.
    pub atlas: String,
}

/// Global lock to synchronize writes to the owned names storage list.
pub static OWNED_NAMES_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Holds the global state for the API server, including network, storage, and authentication.
#[derive(Clone)]
pub struct ApiState {
    /// The P2P network client.
    pub network: NetworkClient,
    /// Local storage engine interface.
    pub storage: Arc<dyn StorageEngine>,
    /// Map of background VDF tasks.
    pub vdf_tasks: Arc<Mutex<HashMap<String, VdfTaskStatus>>>,

    /// API authentication tokens to restrict access by role.
    pub tokens: Arc<ApiTokens>,
    /// Semaphore to restrict concurrent VDF computations.
    pub vdf_semaphore: Arc<tokio::sync::Semaphore>,
    /// The IP address this daemon is bound to.
    pub bind_ip: String,
    /// Gossip channel sender for SSE streams.
    pub gossip_tx: tokio::sync::broadcast::Sender<(
        String,
        Vec<u8>,
        libp2p::gossipsub::MessageId,
        libp2p::PeerId,
    )>,
    /// Set of foreign NSPs registered by the kinetic-atlas bridge.
    pub atlas_nsps: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
}

/// Payload for publishing a direct reveal configuration.
#[derive(Deserialize, Debug)]
pub struct PublishRequest {
    /// The NameRecord object to publish.
    pub record: kinetic_core::types::NameRecord,
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

    let bind_ip = state.bind_ip.clone();
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(
            move |origin: &axum::http::HeaderValue, _request_parts| {
                if let Ok(o) = origin.to_str() {
                    o.starts_with("http://localhost:")
                        || o.starts_with("http://127.0.0.1:")
                        || o.starts_with(&format!("http://{}:", bind_ip))
                        || o.starts_with("http://[::1]:")
                        || o == "http://localhost"
                        || o == "http://127.0.0.1"
                        || o == format!("http://{}", bind_ip)
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
        .route("/commit", post(handle_publish_commit))
        .route("/publish", post(handle_publish_record))
        .route("/publish-kid", post(handle_publish_kid))
        .route("/publish-manifest", post(handle_publish_manifest))
        .route("/publish-governance", post(handle_publish_governance))
        .route("/config", axum::routing::get(handle_get_config))
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
            "/zone/local/{name}",
            axum::routing::post(handle_post_local_zone),
        )
        .route(
            "/zone/local/{name}",
            axum::routing::delete(handle_delete_local_zone),
        )
        .route(
            "/zone/{name}/publish",
            axum::routing::post(handle_publish_zone),
        )
        .route("/kid", axum::routing::post(handle_generate_kid))
        .route("/kid/{name}/rotate", axum::routing::post(handle_rotate_kid))
        .route("/kid/{name}/revoke", axum::routing::post(handle_revoke_kid))
        .route(
            "/kid/{name}/manifest",
            axum::routing::post(handle_update_kid_manifest),
        )
        .route("/vdf/register", axum::routing::post(handle_vdf_register))
        .route("/vdf/renew", axum::routing::post(handle_vdf_renew))
        .route(
            "/gossip/publish/{topic}",
            axum::routing::post(handle_gossip_publish),
        )
        .route(
            "/internal/atlas/sync",
            axum::routing::post(handle_atlas_sync),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let public_api_routes = Router::new()
        .route("/health", axum::routing::get(handle_get_health))
        .route("/peer_id", axum::routing::get(handle_get_peer_id))
        .route("/network-status", axum::routing::get(handle_network_status))
        .route(
            "/names/reserved",
            axum::routing::get(handle_get_reserved_names),
        )
        .route("/governance", axum::routing::get(handle_get_governance))
        .route("/zone/{name}", axum::routing::get(handle_get_zone))
        .route(
            "/zone/local/{name}",
            axum::routing::get(handle_get_local_zone),
        )
        .route("/resolve/{name}", axum::routing::get(handle_resolve_name))
        .route("/resolve-kid/{did}", axum::routing::get(handle_resolve_kid))
        .route("/kid", axum::routing::get(handle_list_kids))
        .route("/kid/{name}", axum::routing::get(handle_fetch_kid))
        .route(
            "/kid/{name}/manifest",
            axum::routing::get(handle_get_kid_manifest),
        )
        .route("/time", axum::routing::get(handle_get_time))
        .route(
            "/gossip/subscribe/{topic}",
            axum::routing::get(handle_gossip_subscribe),
        );

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
            error_code = "KIN-SYS-014",
            severity = "Critical",
            "FATAL: getrandom failed — cannot generate secure API token. Refusing to start with a predictable token. Error: {}",
            e
        );
        anyhow::anyhow!("[KIN-SYS-014] getrandom failed: {}. Cannot generate a secure API token.", e)
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

fn rotate_token_on_boot(token_path: &std::path::Path) -> anyhow::Result<String> {
    tracing::info!(
        "Rotating API token: {:?}",
        token_path.file_name().unwrap_or_default()
    );
    generate_and_write_token(token_path)
}

/// Ensures all API tokens are generated and returns them.
pub fn ensure_api_tokens() -> anyhow::Result<ApiTokens> {
    let tokens_dir = kinetic_core::config::get_api_tokens_dir();

    let admin = rotate_token_on_boot(&tokens_dir.join("admin.token"))?;
    let publish = rotate_token_on_boot(&tokens_dir.join("publish.token"))?;
    let vdf = rotate_token_on_boot(&tokens_dir.join("vdf.token"))?;
    let governance = rotate_token_on_boot(&tokens_dir.join("governance.token"))?;
    let atlas = rotate_token_on_boot(&tokens_dir.join("atlas.token"))?;

    Ok(ApiTokens {
        admin,
        publish,
        vdf,
        governance,
        atlas,
    })
}

/// Starts the HTTP API server on the specified port.
///
/// # Errors
///
/// Returns an error if the server fails to bind to the port or if token generation fails.
pub async fn start_server(
    network: NetworkClient,
    storage: Arc<dyn StorageEngine>,
    gossip_tx: tokio::sync::broadcast::Sender<(
        String,
        Vec<u8>,
        libp2p::gossipsub::MessageId,
        libp2p::PeerId,
    )>,
    bind_ip: String,
    port: u16,
    atlas_nsps: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
) -> anyhow::Result<()> {
    let tokens = ensure_api_tokens()?;

    let state = ApiState {
        network,
        storage,
        vdf_tasks: Arc::new(Mutex::new(HashMap::new())),
        tokens: Arc::new(tokens),
        vdf_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
        bind_ip: bind_ip.clone(),
        gossip_tx,
        atlas_nsps,
    };

    // Start background VDF Mempool worker

    let app = app(state);

    let mut listener = None;
    for _ in 0..10 {
        if let Ok(l) = tokio::net::TcpListener::bind(format!("{}:{}", bind_ip, port)).await {
            listener = Some(l);
            break;
        } else if let Ok(l) = tokio::net::TcpListener::bind(format!("[::1]:{}", port)).await {
            tracing::warn!(
                "KIN-SYS-001: Failed to bind API to {}, successfully bound to IPv6 loopback [::1]",
                bind_ip
            );
            listener = Some(l);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let listener = listener.ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to bind API to {} or [::1] on port {}",
            bind_ip,
            port
        )
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
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let header = match auth_header {
        Some(h) => h,
        None => {
            tracing::warn!("KIN-API-001: Rejecting API request: Missing Authorization header");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    if !header.starts_with("Bearer ") {
        tracing::warn!("KIN-API-001: Rejecting API request: Authorization header is not a Bearer token");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let provided_token = header.trim_start_matches("Bearer ");

    let role = {
        use subtle::ConstantTimeEq;
        let provided_bytes = provided_token.as_bytes();

        let mut matched_role = None;
        let mut check_token = |expected: &str, r: Role| {
            let expected_bytes = expected.as_bytes();
            if provided_bytes.len() == expected_bytes.len()
                && provided_bytes.ct_eq(expected_bytes).unwrap_u8() == 1
            {
                matched_role = Some(r);
            }
        };

        check_token(&state.tokens.admin, Role::Admin);
        check_token(&state.tokens.publish, Role::Publish);
        check_token(&state.tokens.vdf, Role::Vdf);
        check_token(&state.tokens.governance, Role::Governance);
        check_token(&state.tokens.atlas, Role::Atlas);

        matched_role
    };

    match role {
        Some(r) => {
            req.extensions_mut().insert(r);
            Ok(next.run(req).await)
        }
        None => {
            tracing::warn!("KIN-API-001: Rejecting API request: Invalid API token");
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
