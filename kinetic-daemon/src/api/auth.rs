use axum::{extract::{Path, State}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use crate::api::{ApiState, Role};

/// Request payload for creating a new session token.
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateSessionRequest {
    /// The name of the third-party application requesting access.
    pub app_name: String,
    /// The requested scopes for the session (e.g., ["Publish", "Vdf"]).
    pub scopes: Vec<String>,
    /// The Kinetic Network Time (Kyn) when this token expires.
    pub expiry_kyn: u64,
}

/// Represents a persistent session token for an application.
#[derive(Serialize, Deserialize, Debug)]
pub struct AppSession {
    /// The unique public ID for this session (used for revocation).
    pub id: String,
    /// The secure 32-byte token.
    pub token: String,
    /// The name of the authorized application.
    pub app_name: String,
    /// The scopes granted to this session.
    pub scopes: Vec<String>,
    /// Unix timestamp of when the session was created.
    pub created_at: u64,
    /// The Kinetic Network Time (Kyn) when this token expires.
    pub expiry_kyn: u64,
}

/// Response payload for listing all active sessions.
#[derive(Serialize)]
pub struct ListSessionsResponse {
    /// List of active application sessions.
    pub sessions: Vec<AppSession>,
}

/// Handles the creation of a new session token for a local application.
pub async fn handle_create_session(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Requires Admin role"})),
        ));
    }
    
    if req.scopes.iter().any(|s| s.to_lowercase() == "admin") {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Cannot generate secondary Admin tokens"})),
        ));
    }
    
    if req.scopes.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "At least one scope must be requested"})),
        ));
    }

    // Generate a secure 32-byte token
    use rand::RngCore;
    let mut rand_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut rand_bytes);
    let token = hex::encode(rand_bytes);

    let id = uuid::Uuid::new_v4().to_string();

    let session = AppSession {
        id: id.clone(),
        token: token.clone(),
        app_name: req.app_name,
        scopes: req.scopes,
        created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        expiry_kyn: req.expiry_kyn,
    };

    let session_bytes = serde_json::to_vec(&session).unwrap();
    let db_key_session = format!("session:{}", id);
    let db_key_token = format!("session_token:{}", token);
    
    if let Err(e) = state.storage.put(db_key_session.as_bytes(), &session_bytes) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to save session: {}", e)})),
        ));
    }
    
    if let Err(e) = state.storage.put(db_key_token.as_bytes(), id.as_bytes()) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to save session token lookup: {}", e)})),
        ));
    }

    Ok(Json(serde_json::json!({
        "status": "success",
        "id": id,
        "token": token
    })))
}

/// Lists all active application session tokens.
pub async fn handle_list_sessions(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
) -> Result<Json<ListSessionsResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Requires Admin role"})),
        ));
    }

    let mut sessions = Vec::new();
    if let Ok(entries) = state.storage.scan_prefix(b"session:", None) {
        for (k, v) in entries {
            if !k.starts_with(b"session_token:") {
                if let Ok(mut session) = serde_json::from_slice::<AppSession>(&v) {
                    session.token = "hidden".to_string();
                    sessions.push(session);
                }
            }
        }
    }

    Ok(Json(ListSessionsResponse { sessions }))
}

/// Revokes an application session token.
pub async fn handle_revoke_session(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Requires Admin role"})),
        ));
    }

    let db_key_session = format!("session:{}", id);
    
    // First read the session to get the raw token so we can delete the lookup
    if let Ok(Some(bytes)) = state.storage.get(db_key_session.as_bytes()) {
        if let Ok(session) = serde_json::from_slice::<AppSession>(&bytes) {
            let db_key_token = format!("session_token:{}", session.token);
            let _ = state.storage.delete(db_key_token.as_bytes());
        }
    } else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Session not found"})),
        ));
    }

    if let Err(e) = state.storage.delete(db_key_session.as_bytes()) {
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
