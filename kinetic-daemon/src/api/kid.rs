use super::*;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;

/// Request payload to generate or resolve a KID
#[derive(Deserialize)]
pub struct GenerateKidRequest {
    /// The base domain name (e.g., example.kin)
    pub base_name: String,
    /// An optional subname (e.g., admin)
    pub sub_name: Option<String>,
    /// Whether to inherit the apex KID when creating a subname (default true)
    #[serde(default = "default_inherit")]
    pub inherit_subname: bool,
    /// Force overwrite existing local keys (default false)
    #[serde(default)]
    pub force: bool,
}

fn default_inherit() -> bool {
    true
}

/// Handles API requests to list all local KID documents stored on the filesystem.
pub async fn handle_list_kids() -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let summaries = kinetic_core::types::list_local_kids().map_err(|e| {
        let api_err = kinetic_core::ApiError::from(e);
        (
            StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(serde_json::to_value(api_err).unwrap_or_default()),
        )
    })?;

    Ok(Json(serde_json::json!({ "kids": summaries })))
}

/// Handles API requests to retrieve a specific local KID document by its domain name.
pub async fn handle_get_kid(
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (doc, path) = kinetic_core::types::load_local_kid(&name).map_err(|e| {
        let api_err = kinetic_core::ApiError::from(e);
        (
            StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(serde_json::to_value(api_err).unwrap_or_default()),
        )
    })?;

    Ok(Json(serde_json::json!({
        "name": kinetic_core::types::normalize_name(&name),
        "kid_doc": doc,
        "path": path.to_string_lossy(),
    })))
}

/// Handles API requests to generate a new KID document, keypair, and publish it.
pub async fn handle_generate_kid(
    Extension(role): Extension<Role>,
    State(state): State<ApiState>,
    Json(req): Json<GenerateKidRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !role.can_publish() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient privileges: Requires Publish or Admin role"})),
        ));
    }

    let base_fqdn = kinetic_core::types::normalize_name(&req.base_name);
    let final_name = if let Some(sub) = req.sub_name {
        format!("{}.{}", sub, base_fqdn)
    } else {
        base_fqdn
    };

    let res = kinetic_core::types::get_or_create_kid_for_name(
        &final_name,
        req.inherit_subname,
        req.force,
    )
    .map_err(|e| {
        let api_err = kinetic_core::ApiError::from(e);
        (
            StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(serde_json::to_value(api_err).unwrap_or_default()),
        )
    })?;

    // Publish AuthorizedKid wrapper to DHT
    if let Ok(payload_bytes) = serde_json::to_vec(&res.auth_kid) {
        let _ = state
            .network
            .publish_redundant_payload(&res.did, payload_bytes)
            .await;
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "name": res.name,
        "did": res.did,
        "is_inherited": res.is_inherited,
        "kid_doc": res.kid_doc
    })))
}

/// Handles API requests to rotate the keys of a local KID document and publish the update.
pub async fn handle_rotate_kid(
    Extension(role): Extension<Role>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !role.can_publish() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient privileges: Requires Publish or Admin role"})),
        ));
    }

    let rotated = kinetic_core::types::rotate_name_kid(&name).map_err(|e| {
        let api_err = kinetic_core::ApiError::from(e);
        (
            StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(serde_json::to_value(api_err).unwrap_or_default()),
        )
    })?;

    // Publish rotated document to DHT
    if let Ok(payload_bytes) = serde_json::to_vec(&rotated.auth_kid) {
        let _ = state
            .network
            .publish_redundant_payload(&rotated.did, payload_bytes)
            .await;
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "name": rotated.name,
        "did": rotated.did,
        "kid_doc": rotated.kid_doc
    })))
}
