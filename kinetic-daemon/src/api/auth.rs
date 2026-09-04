use axum::{extract::{Path, State}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use crate::api::{ApiState, Role};

/// Request payload for creating a new session token.
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateSessionRequest {
    /// The name of the third-party application requesting access.
    pub app_name: String,
    /// The requested role/scope for the session (e.g., "Publish").
    pub role: String,
}

/// Represents a persistent session token for an application.
#[derive(Serialize, Deserialize, Debug)]
pub struct AppSession {
    /// The secure 32-byte token.
    pub token: String,
    /// The name of the authorized application.
    pub app_name: String,
    /// The role granted to this session.
    pub role: String,
    /// Unix timestamp of when the session was created.
    pub created_at: u64,
}

/// Response payload for listing all active sessions.
#[derive(Serialize)]
pub struct ListSessionsResponse {
    /// List of active application sessions.
    pub sessions: Vec<AppSession>,
}

/// Parses a string into a `Role` enum.
pub fn parse_role(role_str: &str) -> Option<Role> {
    match role_str.to_lowercase().as_str() {
        "admin" => Some(Role::Admin),
        "publish" => Some(Role::Publish),
        "vdf" => Some(Role::Vdf),
        "governance" => Some(Role::Governance),
        "atlas" => Some(Role::Atlas),
        _ => None,
    }
}

/// Handles the creation of a new session token for a local application.
pub async fn handle_create_session(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !matches!(role, Role::Admin) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Requires Admin role"})),
        ));
    }
    
    if parse_role(&req.role).is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid role"})),
        ));
    }

    // Generate a secure 32-byte token
    use rand::RngCore;
    let mut rand_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut rand_bytes);
    let token = hex::encode(rand_bytes);

    let session = AppSession {
        token: token.clone(),
        app_name: req.app_name,
        role: req.role,
        created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
    };

    let session_bytes = serde_json::to_vec(&session).unwrap();
    let db_key = format!("session:{}", token);
    
    if let Err(e) = state.storage.put(db_key.as_bytes(), &session_bytes) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to save session: {}", e)})),
        ));
    }

    Ok(Json(serde_json::json!({
        "status": "success",
        "token": token
    })))
}

/// Lists all active application session tokens.
pub async fn handle_list_sessions(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
) -> Result<Json<ListSessionsResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !matches!(role, Role::Admin) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Requires Admin role"})),
        ));
    }

    let mut sessions = Vec::new();
    if let Ok(entries) = state.storage.scan_prefix(b"session:", None) {
        for (_k, v) in entries {
            if let Ok(session) = serde_json::from_slice::<AppSession>(&v) {
                sessions.push(session);
            }
        }
    }

    Ok(Json(ListSessionsResponse { sessions }))
}

/// Revokes an application session token.
pub async fn handle_revoke_session(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
    Path(token): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !matches!(role, Role::Admin) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Requires Admin role"})),
        ));
    }

    let db_key = format!("session:{}", token);
    if let Err(e) = state.storage.delete(db_key.as_bytes()) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to revoke session: {}", e)})),
        ));
    }

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Session revoked"
    })))
}
