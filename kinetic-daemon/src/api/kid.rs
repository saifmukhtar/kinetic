use super::*;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use kinetic_core::types::AuthorizedKid;
use ml_dsa::{Generate, KeyExport, Keypair, SignatureEncoding};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
use sha2::Digest;
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Request payload to generate a new KID
#[derive(Deserialize)]
pub struct GenerateKidRequest {
    /// The base domain name (e.g., example.kin)
    pub base_name: String,
    /// An optional subname (e.g., admin)
    pub sub_name: Option<String>,
}

fn get_kids_dir() -> std::path::PathBuf {
    kinetic_core::config::get_base_dir().join("kids")
}

/// Handles API requests to list all local KID documents stored on the filesystem.
pub async fn handle_list_kids() -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let kid_dir = get_kids_dir();
    let mut kids = Vec::new();
    
    if let Ok(entries) = std::fs::read_dir(kid_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(doc) = serde_json::from_str::<kinetic_kid::document::KidDocument>(&content) {
                            kids.push(serde_json::json!({
                                "name": name,
                                "kid_doc": doc
                            }));
                        }
                    }
                }
            }
        }
    }
    
    Ok(Json(serde_json::json!({ "kids": kids })))
}

/// Handles API requests to retrieve a specific local KID document by its domain name.
pub async fn handle_get_kid(
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    let path = get_kids_dir().join(format!("{}.json", fqdn));
    
    if let Ok(content) = std::fs::read_to_string(path) {
        if let Ok(doc) = serde_json::from_str::<kinetic_kid::document::KidDocument>(&content) {
            return Ok(Json(serde_json::json!({
                "name": fqdn,
                "kid_doc": doc
            })));
        }
    }
    
    Err((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "KID not found" })),
    ))
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
        base_fqdn.clone()
    };
    
    let kid_dir = get_kids_dir();
    std::fs::create_dir_all(&kid_dir).unwrap_or_default();
    
    // 1. Generate new ML-DSA-65 keypair
    let kid_keypair = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::generate();
    let pk_bytes = kid_keypair.verifying_key().to_bytes();
    let pk_b64 = b64_url.encode(pk_bytes);
    
    // 2. Hash pubkey for DID
    let mut hasher = sha2::Sha256::new();
    hasher.update(pk_bytes);
    let did_string = format!(
        "{}{}",
        kinetic_core::constants::DID_PREFIX,
        hex::encode(hasher.finalize())
    );
    let did = kinetic_kid::did::KineticDid::new(&did_string)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Invalid DID: {}", e)}))))?;
        
    let controller_key = kinetic_kid::document::ControllerKey {
        id: format!("{}#key-1", did.as_str()),
        key_type: "ML-DSA-65".to_string(),
        public_key: pk_b64,
    };
    
    // 3. Construct Document
    let doc = kinetic_kid::document::KidDocument {
        doc_type: "kinetic.kid.v1".to_string(),
        kid: did.clone(),
        created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        controller_keys: vec![controller_key],
        manifest: None,
        revocation_keys: vec![],
        deactivated: false,
        signature: None,
    };
    
    let signed_doc = doc.sign(&kid_keypair)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to sign KID doc: {}", e)}))))?;
        
    // 4. Save to filesystem
    let doc_path = kid_dir.join(format!("{}.json", final_name));
    let key_path = kid_dir.join(format!("{}.key", final_name));
    
    let doc_json = serde_json::to_string_pretty(&signed_doc).unwrap_or_default();
    let _ = std::fs::write(&doc_path, doc_json);
    let _ = std::fs::write(&key_path, kid_keypair.to_bytes());
    
    // 5. Wrap in AuthorizedKid
    let mut auth_kid = AuthorizedKid {
        name: final_name.clone(),
        kid_doc: signed_doc.clone(),
        owner_signature: vec![],
    };
    
    // 6. Sign AuthorizedKid wrapper with the daemon's main identity key (owner of the name)
    let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
    if let Ok(identity_keypair) = kinetic_core::types::load_keypair(&identity_path.to_string_lossy()) {
        use ml_dsa::signature::Signer;
        let signable = auth_kid.signable_bytes(kinetic_core::constants::NETWORK_ID);
        auth_kid.owner_signature = identity_keypair.sign(&signable).to_bytes().to_vec();
        
        // 7. Publish to DHT
        if let Ok(payload_bytes) = serde_json::to_vec(&auth_kid) {
            let _ = state.network.publish_redundant_payload(did.as_str(), payload_bytes).await;
        }
    }
    
    Ok(Json(serde_json::json!({
        "success": true,
        "name": final_name,
        "kid_doc": signed_doc
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
    
    let fqdn = kinetic_core::types::normalize_name(&name);
    let kid_dir = get_kids_dir();
    let doc_path = kid_dir.join(format!("{}.json", fqdn));
    let key_path = kid_dir.join(format!("{}.key", fqdn));
    
    if !doc_path.exists() || !key_path.exists() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Local KID or key file not found"})),
        ));
    }
    
    let kid_data = std::fs::read_to_string(&doc_path).unwrap_or_default();
    let mut doc: kinetic_kid::document::KidDocument = serde_json::from_str(&kid_data)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to parse local KID"}))))?;
        
    // 1. Generate new controller key
    let new_keypair = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::generate();
    let new_pub_b64 = b64_url.encode(new_keypair.verifying_key().to_bytes());
    
    let primary_id = format!("{}#primary", doc.kid);
    doc.controller_keys = vec![kinetic_kid::document::ControllerKey {
        id: primary_id,
        key_type: "ML-DSA-65".to_string(),
        public_key: new_pub_b64,
    }];
    
    // 2. Load old key to sign the rotation update
    let old_key_data = std::fs::read(&key_path).unwrap_or_default();
    if old_key_data.len() != 32 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Old key file is corrupted"})),
        ));
    }
    
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&old_key_data);
    let old_signing_key = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed((&seed).into());
    
    let signed_doc = doc.sign(&old_signing_key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to sign rotated KID: {}", e)}))))?;
        
    // 3. Save new files
    let doc_json = serde_json::to_string_pretty(&signed_doc).unwrap_or_default();
    let _ = std::fs::write(&doc_path, doc_json);
    let _ = std::fs::write(&key_path, new_keypair.to_bytes());
    
    // 4. Wrap in AuthorizedKid
    let mut auth_kid = AuthorizedKid {
        name: fqdn.clone(),
        kid_doc: signed_doc.clone(),
        owner_signature: vec![],
    };
    
    // 5. Sign AuthorizedKid wrapper with the daemon's main identity key
    let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
    if let Ok(identity_keypair) = kinetic_core::types::load_keypair(&identity_path.to_string_lossy()) {
        use ml_dsa::signature::Signer;
        let signable = auth_kid.signable_bytes(kinetic_core::constants::NETWORK_ID);
        auth_kid.owner_signature = identity_keypair.sign(&signable).to_bytes().to_vec();
        
        // 6. Publish to DHT
        if let Ok(payload_bytes) = serde_json::to_vec(&auth_kid) {
            let _ = state.network.publish_redundant_payload(signed_doc.kid.as_str(), payload_bytes).await;
        }
    }
    
    Ok(Json(serde_json::json!({
        "success": true,
        "name": fqdn,
        "kid_doc": signed_doc
    })))
}
