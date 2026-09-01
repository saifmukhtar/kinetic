use super::*;
use kinetic_core::traits::KynProvider;
use axum::{
    Json,
    extract::{Extension, Path, State},
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
pub async fn handle_list_kids() -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    let summaries = kinetic_core::types::list_local_kids()?;
    Ok(Json(serde_json::json!({ "kids": summaries })))
}

/// Handles API requests to retrieve a specific local KID document by its domain name.
pub async fn handle_fetch_kid(
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    let (doc, path) = kinetic_core::types::load_local_kid(&name)?;
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
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_publish() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges
        ));
    }

    let base_fqdn = kinetic_core::types::normalize_name(&req.base_name);
    let final_name = if let Some(sub) = req.sub_name {
        format!("{}.{}", sub, base_fqdn)
    } else {
        base_fqdn
    };

    let drand_client = kinetic_core::drand::DrandProvider::new(Some(state.storage.clone()));
    use kinetic_core::types::clock::KynNetworkExt;
    use kinetic_core::types::Kyn;
    
    let current_kyn = match drand_client.fetch_latest().await {
        Ok(kyn) => Kyn(kyn.kyn),
        Err(_) => Kyn::now_local(),
    };

    let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
    let res = kinetic_core::types::get_or_create_kid_for_name(
        &final_name,
        req.inherit_subname,
        req.force,
        current_kyn,
        &identity_path,
    )?;

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
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_publish() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges
        ));
    }

    let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
    let rotated = kinetic_core::types::rotate_name_kid(&name, &identity_path)?;

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

/// Handles API requests to revoke (deactivate) a local KID document and publish the revocation.
pub async fn handle_revoke_kid(
    Extension(role): Extension<Role>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_publish() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges
        ));
    }

    let revoked_doc = kinetic_core::types::revoke_local_kid(&name)?;

    let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
    let auth_kid = kinetic_core::types::authorize_kid_document(&name, &revoked_doc, &identity_path)?;

    // Publish revoked document to DHT
    if let Ok(payload_bytes) = serde_json::to_vec(&auth_kid) {
        let _ = state
            .network
            .publish_redundant_payload(revoked_doc.kid.as_str(), payload_bytes)
            .await;
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "name": kinetic_core::types::normalize_name(&name),
        "did": revoked_doc.kid.as_str(),
        "deactivated": true,
        "kid_doc": revoked_doc
    })))
}

/// Retrieves the locally stored Manifest for a given identity name if present.
pub async fn handle_get_kid_manifest(
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    let manifest = kinetic_core::types::load_local_manifest(&name)?;
    Ok(Json(serde_json::json!({
        "name": kinetic_core::types::normalize_name(&name),
        "manifest": manifest,
    })))
}

/// Request payload for updating an identity's capability manifest.
#[derive(serde::Deserialize)]
pub struct UpdateManifestRequest {
    /// List of service entries to publish in the manifest.
    pub services: Vec<kinetic_kid::manifest::Service>,
}

/// Creates, signs, persists, and publishes a new version of the capability manifest for an identity.
pub async fn handle_update_kid_manifest(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Json(req): Json<UpdateManifestRequest>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_publish() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges
        ));
    }

    let drand_client = kinetic_core::drand::DrandProvider::new(Some(state.storage.clone()));
    use kinetic_core::types::clock::KynNetworkExt;
    use kinetic_core::types::Kyn;
    
    let current_kyn = match drand_client.fetch_latest().await {
        Ok(kyn) => Kyn(kyn.kyn),
        Err(_) => Kyn::now_local(),
    };

    let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
    let (manifest, auth_manifest) = kinetic_core::types::save_and_sign_local_manifest(
        &name,
        req.services,
        current_kyn,
        &identity_path,
    )?;

    // Publish to DHT under hex(sha256(did#manifest))
    let manifest_key = hex::encode(kinetic_primitives::sha256_hash(format!("{}#manifest", manifest.kid).as_bytes()));

    if let Ok(payload_bytes) = serde_json::to_vec(&auth_manifest) {
        let _ = state
            .network
            .publish_redundant_payload(&manifest_key, payload_bytes)
            .await;
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "name": kinetic_core::types::normalize_name(&name),
        "manifest": manifest,
    })))
}
