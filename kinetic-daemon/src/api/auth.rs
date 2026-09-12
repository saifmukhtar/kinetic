use crate::api::{ApiState, Role};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};

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
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.is_admin() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    if req.scopes.iter().any(|s| s.to_lowercase() == "admin") {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::BadRequest(
                "Cannot generate secondary Admin tokens".to_string(),
            ),
        ));
    }

    if req.scopes.is_empty() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::BadRequest(
                "At least one scope must be requested".to_string(),
            ),
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
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        expiry_kyn: req.expiry_kyn,
    };

    let session_bytes = serde_json::to_vec(&session).unwrap();
    let db_key_session = format!("session:{}", id);
    let db_key_token = format!("session_token:{}", token);

    let storage_clone = state.storage.clone();
    let id_for_storage = id.clone();
    tokio::task::spawn_blocking(move || -> Result<(), Box<crate::api::error::AppError>> {
        if let Err(e) = storage_clone.put(db_key_session.as_bytes(), &session_bytes) {
            return Err(Box::new(e.into()));
        }
        if let Err(e) = storage_clone.put(db_key_token.as_bytes(), id_for_storage.as_bytes()) {
            return Err(Box::new(e.into()));
        }
        Ok(())
    })
    .await
    .map_err(|_| {
        crate::api::error::AppError::from(kinetic_core::error::SystemError::ServerCrashed(
            "Async blocking pool panicked".into(),
        ))
    })?
    .map_err(|e| *e)?;

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
) -> Result<Json<ListSessionsResponse>, crate::api::error::AppError> {
    if !role.is_admin() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    let storage_clone = state.storage.clone();
    let sessions = tokio::task::spawn_blocking(move || {
        let mut sessions = Vec::new();
        if let Ok(entries) = storage_clone.scan_prefix(b"session:", None) {
            for (k, v) in entries {
                if !k.starts_with(b"session_token:")
                    && let Ok(mut session) = serde_json::from_slice::<AppSession>(&v)
                {
                    session.token = "hidden".to_string();
                    sessions.push(session);
                }
            }
        }
        sessions
    })
    .await
    .map_err(|_| {
        crate::api::error::AppError::from(kinetic_core::error::SystemError::ServerCrashed(
            "Async blocking pool panicked".into(),
        ))
    })?;

    Ok(Json(ListSessionsResponse { sessions }))
}

/// Revokes an application session token.
pub async fn handle_revoke_session(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.is_admin() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    let storage_clone = state.storage.clone();
    tokio::task::spawn_blocking(move || -> Result<(), Box<crate::api::error::AppError>> {
        let db_key_session = format!("session:{}", id);

        // First read the session to get the raw token so we can delete the lookup
        if let Ok(Some(bytes)) = storage_clone.get(db_key_session.as_bytes()) {
            if let Ok(session) = serde_json::from_slice::<AppSession>(&bytes) {
                let db_key_token = format!("session_token:{}", session.token);
                let _ = storage_clone.delete(db_key_token.as_bytes());
            }
        } else {
            return Err(Box::new(kinetic_core::error::RestApiError::NotFound.into()));
        }

        if let Err(e) = storage_clone.delete(db_key_session.as_bytes()) {
            return Err(Box::new(e.into()));
        }

        Ok(())
    })
    .await
    .map_err(|_| {
        crate::api::error::AppError::from(kinetic_core::error::SystemError::ServerCrashed(
            "Async blocking pool panicked".into(),
        ))
    })?
    .map_err(|e| *e)?;

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Session revoked"
    })))
}
