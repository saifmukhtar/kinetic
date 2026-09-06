use super::*;
use axum::{
    Json,
    extract::{Extension, Path, State},
};
use kinetic_core::traits::KynProvider;
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
    let summaries = kinetic_local::kid_manager::list_local_kids()?;
    Ok(Json(serde_json::json!({ "kids": summaries })))
}

/// Handles API requests to retrieve a specific local KID document by its domain name.
pub async fn handle_fetch_kid(
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    let (doc, path) = kinetic_local::kid_manager::load_local_kid(&name)?;
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
    if !role.can_kid() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    let base_fqdn = kinetic_core::types::normalize_name(&req.base_name);
    let final_name = if let Some(sub) = req.sub_name {
        format!("{}.{}", sub, base_fqdn)
    } else {
        base_fqdn
    };

    let kyn_provider =
        kinetic_network::client::drand::DrandProvider::new(Some(state.storage.clone()));
    use kinetic_core::types::Kyn;
    use kinetic_core::types::clock::KynNetworkExt;

    let current_kyn = match kyn_provider.fetch_latest().await {
        Ok(kyn) => Kyn(kyn.kyn),
        Err(_) => Kyn::now_local(),
    };

    let identity_path = kinetic_local::config::get_base_dir().join("identity.key");
    let res = kinetic_local::kid_manager::get_or_create_kid_for_name(
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
    if !role.can_kid() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    let identity_path = kinetic_local::config::get_base_dir().join("identity.key");
    let rotated = kinetic_local::kid_manager::rotate_name_kid(&name, &identity_path)?;

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
    if !role.can_kid() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    let revoked_doc = kinetic_local::kid_manager::revoke_local_kid(&name)?;

    let identity_path = kinetic_local::config::get_base_dir().join("identity.key");
    let auth_kid =
        kinetic_local::kid_manager::authorize_kid_document(&name, &revoked_doc, &identity_path)?;

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
    let manifest = kinetic_local::kid_manager::load_local_manifest(&name)?;
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
    if !role.can_kid() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    let kyn_provider =
        kinetic_network::client::drand::DrandProvider::new(Some(state.storage.clone()));
    use kinetic_core::types::Kyn;
    use kinetic_core::types::clock::KynNetworkExt;

    let current_kyn = match kyn_provider.fetch_latest().await {
        Ok(kyn) => Kyn(kyn.kyn),
        Err(_) => Kyn::now_local(),
    };

    let identity_path = kinetic_local::config::get_base_dir().join("identity.key");
    let (manifest, auth_manifest) = kinetic_local::kid_manager::save_and_sign_local_manifest(
        &name,
        req.services,
        current_kyn,
        &identity_path,
    )?;

    // Publish to DHT under hex(sha256(did#manifest))
    let manifest_key = hex::encode(kinetic_primitives::sha256_hash(
        format!("{}#manifest", manifest.kid).as_bytes(),
    ));

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

/// Handles API requests to resolve a Kinetic Identifier (KID) and its associated manifest.
///
/// # Errors
///
/// Returns an error if the KID cannot be found in the DHT, or if the retrieved payload is invalid.
pub async fn handle_resolve_kid(
    State(state): State<ApiState>,
    Path(did): Path<String>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    tracing::info!("Resolving KID via API: {}", did);

    // Resolve KID - Notice how this entire massive match block is now just a single `?`
    let kid_payload = state.network.resolve_redundant_payload(&did).await?;

    let kid_doc: kinetic_kid::Document =
        match serde_json::from_slice::<kinetic_core::types::AuthorizedKid>(&kid_payload) {
            Ok(auth) => auth.kid_doc,
            Err(_) => {
                // Fallback for older raw documents
                serde_json::from_slice(&kid_payload).map_err(|_| {
                    kinetic_core::error::ResolutionError::Internal {
                        message: "Invalid KID data payload".to_string(),
                        source: None,
                    }
                })?
            }
        };

    // Try to resolve Manifest
    let manifest_key = hex::encode(kinetic_primitives::sha256_hash(
        format!("{}#manifest", did).as_bytes(),
    ));

    let mut res = serde_json::json!({
        "kid_document": kid_doc,
    });

    if let Ok(man_payload) = state.network.resolve_redundant_payload(&manifest_key).await {
        let manifest_opt =
            match serde_json::from_slice::<kinetic_core::types::AuthorizedManifest>(&man_payload) {
                Ok(auth) => Some(auth.manifest),
                Err(_) => serde_json::from_slice::<kinetic_kid::Manifest>(&man_payload).ok(),
            };

        if let Some(manifest) = manifest_opt
            && let Ok(val) = serde_json::to_value(manifest)
        {
            res["manifest_document"] = val;
        }
    }

    Ok(Json(res))
}

use axum::http::StatusCode;
/// Handles requests to publish an AuthorizedKID to the DHT/Gossip network.
pub async fn handle_publish_kid(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
    Json(auth_kid): Json<kinetic_core::types::AuthorizedKid>,
) -> Result<Json<PublishResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !role.can_kid() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({"error": "Insufficient privileges: Requires Kid or Admin role"}),
            ),
        ));
    }
    tracing::info!(
        "Received API publish request for KID: {}",
        auth_kid.kid_doc.kid.as_str()
    );

    // 1. Verify the underlying KID document mathematically
    if let Err(e) = auth_kid.kid_doc.verify() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid KID signature: {}", e)})),
        ));
    }

    // 1b. Verify the wrapper signature against the registered name's Reveal locally.
    // If it fails here, we reject early and don't spam the DHT.
    let reveal_key = format!(
        "{}{}",
        kinetic_core::constants::DB_PREFIX_REVEAL,
        auth_kid.name
    );
    let is_authorized = match state.storage.get(reveal_key.as_bytes()) {
        Ok(Some(bytes)) => {
            if let Ok(record) = serde_json::from_slice::<kinetic_core::types::NameRecord>(&bytes) {
                kinetic_primitives::verify_mldsa(
                    record.pubkey(),
                    &auth_kid.signable_bytes(kinetic_core::constants::NETWORK_SALT),
                    &auth_kid.owner_signature,
                )
                .is_ok()
            } else {
                false
            }
        }
        _ => {
            let err =
                kinetic_core::error::PublishError::MissingLocalRevealForKid(auth_kid.name.clone());
            tracing::warn!(error_code = err.code(), "{}", err);
            true // If we don't have it cached, we let the network decide.
        }
    };

    if !is_authorized {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(
                serde_json::json!({"error": "Invalid authorization signature. The AuthorizedKid must be signed by the name's owner."}),
            ),
        ));
    }

    // 2. Serialize and Publish to DHT
    let payload_bytes = match serde_json::to_vec(&auth_kid) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Serialization failed: {}", e)})),
            ));
        }
    };
    let fqdn = auth_kid.kid_doc.kid.as_str().to_string(); // Use DID as the DHT key

    match state
        .network
        .publish_redundant_payload(&fqdn, payload_bytes)
        .await
    {
        Ok(_) => {
            tracing::info!("Successfully published KID {} to the DHT", fqdn);
            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "AuthorizedKID accepted and routed to DHT".to_string(),
            }))
        }
        Err(e) => {
            let err = kinetic_core::error::PublishError::KidPublishFailed(e.to_string());
            tracing::error!(error_code = err.code(), "{}", err);
            let api_err = kinetic_rpc::ApiError::from(e);
            Err((
                StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(serde_json::to_value(api_err).unwrap_or_default()),
            ))
        }
    }
}

/// Handles API requests to publish an `AuthorizedManifest` to the DHT.
///
/// # Errors
///
/// Returns an error if the local owner signature check fails, the corresponding KID Document
/// cannot be resolved or verified, or if publishing to the DHT fails.
pub async fn handle_publish_manifest(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
    Json(auth_manifest): Json<kinetic_core::types::AuthorizedManifest>,
) -> Result<Json<PublishResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !role.can_kid() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({"error": "Insufficient privileges: Requires Kid or Admin role"}),
            ),
        ));
    }
    let did_str = auth_manifest.manifest.kid.as_str();
    tracing::info!(
        "Received API publish request for Manifest of KID: {}",
        did_str
    );

    // 1b. Verify the wrapper signature against the registered name's Reveal locally.
    let reveal_key = format!(
        "{}{}",
        kinetic_core::constants::DB_PREFIX_REVEAL,
        auth_manifest.name
    );
    let is_authorized = match state.storage.get(reveal_key.as_bytes()) {
        Ok(Some(bytes)) => {
            if let Ok(record) = serde_json::from_slice::<kinetic_core::types::NameRecord>(&bytes) {
                kinetic_primitives::verify_mldsa(
                    record.pubkey(),
                    &auth_manifest.signable_bytes(kinetic_core::constants::NETWORK_SALT),
                    &auth_manifest.owner_signature,
                )
                .is_ok()
            } else {
                false
            }
        }
        _ => {
            let err = kinetic_core::error::PublishError::MissingLocalRevealForManifest(
                auth_manifest.name.clone(),
            );
            tracing::warn!(error_code = err.code(), "{}", err);
            true
        }
    };

    if !is_authorized {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(
                serde_json::json!({"error": "Invalid authorization signature. The AuthorizedManifest must be signed by the name's owner."}),
            ),
        ));
    }

    // 1. Resolve the KID Document from DHT to verify against
    // (Note: The DHT payload for a KID will now be an AuthorizedKid wrapper!)
    let kid_payload = match state.network.resolve_redundant_payload(did_str).await {
        Ok(p) => p,
        Err(e) => {
            let status = match e {
                kinetic_core::error::ResolutionError::NotFound { .. } => StatusCode::NOT_FOUND,
                kinetic_core::error::ResolutionError::Offline => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return Err((
                status,
                Json(serde_json::json!({"error": format!("DHT lookup failed: {}", e)})),
            ));
        }
    };

    let kid_doc: kinetic_kid::Document =
        match serde_json::from_slice::<kinetic_core::types::AuthorizedKid>(&kid_payload) {
            Ok(auth_kid) => auth_kid.kid_doc,
            Err(_) => {
                // Fallback for older raw Documents if any exist
                match serde_json::from_slice::<kinetic_kid::Document>(&kid_payload) {
                    Ok(doc) => doc,
                    Err(_) => {
                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error": "Invalid KID payload on DHT"})),
                        ));
                    }
                }
            }
        };

    // 2. Verify the manifest against the registered KID using network time
    let current_network_time =
        match kinetic_network::client::drand::DrandProvider::new(Some(state.storage.clone()))
            .load_cached_kyn()
        {
            Ok(raw_kyn) => {
                use kinetic_core::types::clock::KynNetworkExt;
                kinetic_core::types::Kyn(raw_kyn.kyn).to_network_utime().0
            }
            Err(_) => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
    if let Err(e) = auth_manifest
        .manifest
        .verify_at_time(&kid_doc, current_network_time)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid Manifest signature: {}", e)})),
        ));
    }

    // 3. Serialize and Publish to DHT under the derived manifest key
    let manifest_key = hex::encode(kinetic_primitives::sha256_hash(
        format!("{}#manifest", did_str).as_bytes(),
    ));

    let payload_bytes = match serde_json::to_vec(&auth_manifest) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Serialization failed: {}", e)})),
            ));
        }
    };
    match state
        .network
        .publish_redundant_payload(&manifest_key, payload_bytes)
        .await
    {
        Ok(_) => {
            tracing::info!("Successfully published Manifest for {} to the DHT", did_str);
            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "Manifest accepted and routed to DHT".to_string(),
            }))
        }
        Err(e) => {
            let err = kinetic_core::error::PublishError::ManifestPublishFailed(e.to_string());
            tracing::error!(error_code = err.code(), "{}", err);
            let api_err = kinetic_rpc::ApiError::from(e);
            Err((
                StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(serde_json::to_value(api_err).unwrap_or_default()),
            ))
        }
    }
}
