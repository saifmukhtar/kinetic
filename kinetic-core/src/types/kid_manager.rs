//! Canonical Key Identifier (KID) Management Engine for the Kinetic Network.
//!
//! This module provides a single source of truth for creating, inheriting, loading,
//! listing, and cryptographically rotating post-quantum Key Identifier (KID) documents
//! and their underlying ML-DSA-65 keys across the CLI, Daemon, and Network layers.
//!
//! ## Core Invariants & The 4 Identity Cases
//!
//! 1. **Case 1 (New Apex Domain)**: Generates a new dedicated ML-DSA-65 keypair (`kids/{name}.key`)
//!    and a unique `KidDocument` (`did:kin:<SHA256(PublicKey)>`). Overwrites are rejected unless `force = true`.
//! 2. **Case 2 (Subname Inheritance - Default)**: Subdomains (e.g. `blog.saif.kin`) inherit their parent's
//!    apex KID (`did:kin:...`) from `kids/{apex}.json`, avoiding key sprawl.
//! 3. **Case 3 (Subname Isolation - Opt-In)**: Subdomains generate an isolated, independent KID and keypair
//!    for delegated or untrusted sub-services (`inherit_subname = false`).
//! 4. **Case 4 (Cryptographic Key Rotation)**: Rotates the ML-DSA-65 controller key of a name while keeping
//!    the DID string constant. The update is cryptographically signed by the *previous* key to satisfy
//!    DHT verification rules (`is_authorized_update`).
//!
//! All KID operations wrap the resulting document in an [`AuthorizedKid`] container signed by the node's
//! master `identity.key` (the domain owner).

#![cfg(not(target_arch = "wasm32"))]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
use ml_dsa::signature::Signer;
use ml_dsa::{Generate, KeyExport, KeyInit, Keypair, MlDsa65, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::constants::{DID_PREFIX, NETWORK_ID};
use crate::error::IdentityError;
use crate::types::identity::load_keypair;
use crate::types::names::{extract_apex_name, normalize_name};
use kinetic_kid::document::{ControllerKey, KidDocument};
use kinetic_kid::manifest::{CapabilityManifest, ServiceEntry};
use kinetic_kid::KineticDid;
use kinetic_types::identity::{AuthorizedKid, AuthorizedManifest};

/// Metadata and payloads resulting from a generated or inherited KID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedKid {
    /// Fully qualified domain name this KID is bound to (e.g. "saif.kin" or "blog.saif.kin").
    pub name: String,
    /// The W3C DID string (e.g. "did:kin:<hash>").
    pub did: String,
    /// The inner signed [`KidDocument`].
    pub kid_doc: KidDocument,
    /// The outer [`AuthorizedKid`] envelope signed by the master `identity.key`.
    pub auth_kid: AuthorizedKid,
    /// Path to the KID JSON document file on disk.
    pub doc_path: PathBuf,
    /// Path to the private key file on disk (`None` if inherited from apex).
    pub key_path: Option<PathBuf>,
    /// Whether this KID was inherited from an apex domain.
    pub is_inherited: bool,
}

/// Metadata and payloads resulting from a cryptographically rotated KID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotatedKid {
    /// Fully qualified domain name whose KID was rotated.
    pub name: String,
    /// The unchanged DID string.
    pub did: String,
    /// The newly rotated and signed [`KidDocument`].
    pub kid_doc: KidDocument,
    /// The outer [`AuthorizedKid`] envelope signed by the master `identity.key`.
    pub auth_kid: AuthorizedKid,
    /// Path to the updated KID JSON document file on disk.
    pub doc_path: PathBuf,
    /// Path to the new private key file on disk.
    pub key_path: PathBuf,
}

/// Summary of a locally stored KID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalKidSummary {
    /// Name corresponding to the KID document.
    pub name: String,
    /// The W3C DID string.
    pub did: String,
    /// UNIX timestamp when the document was created.
    pub created_at: u64,
    /// Path to the JSON document file.
    pub doc_path: PathBuf,
    /// Whether the corresponding private key exists locally.
    pub has_key: bool,
    /// Whether this document is deactivated.
    pub deactivated: bool,
}

/// Returns the canonical directory where local KID documents and keys are stored (`{base_dir}/kids/`).
pub fn get_kids_dir() -> PathBuf {
    crate::config::get_base_dir().join("kids")
}

/// Returns the current network-anchored Unix timestamp (seconds).
///
/// Derives the network time by mapping the estimated Drand kyn to exact Unix
/// seconds aligned to 3-second network heartbeats using network constants.
pub fn current_network_unix_timestamp() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let estimated_kyn = crate::types::clock::unix_secs_to_network_kyn(now);
    crate::types::clock::network_kyn_to_unix_secs(estimated_kyn)
}

/// Resolves the filesystem paths for a domain's KID document and private key.
pub fn get_kid_paths(name: &str) -> (PathBuf, PathBuf) {
    let fqdn = normalize_name(name);
    let dir = get_kids_dir();
    (
        dir.join(format!("{}.json", fqdn)),
        dir.join(format!("{}.key", fqdn)),
    )
}

/// Atomically writes a private key file with POSIX `0o600` permissions.
fn write_private_key_securely(path: &Path, key_bytes: &[u8]) -> Result<(), IdentityError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp_path);

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts.open(&tmp_path)?;
    file.write_all(key_bytes)?;
    file.sync_all()?;
    fs::rename(tmp_path, path)?;

    Ok(())
}

/// Atomically writes a JSON document file.
fn write_json_document(path: &Path, json_str: &str) -> Result<(), IdentityError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp_path);

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    let mut file = opts.open(&tmp_path)?;
    file.write_all(json_str.as_bytes())?;
    file.sync_all()?;
    fs::rename(tmp_path, path)?;

    Ok(())
}

/// Loads a raw ML-DSA-65 signing key from disk.
fn load_raw_signing_key(path: &Path) -> Result<SigningKey<MlDsa65>, IdentityError> {
    if !path.exists() {
        return Err(IdentityError::KidNotFound(
            path.to_string_lossy().to_string(),
        ));
    }
    let bytes = fs::read(path)?;
    SigningKey::<MlDsa65>::new_from_slice(&bytes).map_err(|_| {
        IdentityError::CorruptedIdentityFile(format!("Invalid key bytes in {:?}", path))
    })
}

/// Wraps a [`KidDocument`] in an [`AuthorizedKid`] envelope and signs it with the master `identity.key`.
pub fn authorize_kid_document(
    name: &str,
    doc: &KidDocument,
) -> Result<AuthorizedKid, IdentityError> {
    let fqdn = normalize_name(name);
    let identity_keypair = load_keypair("identity.key")?;

    let mut auth_kid = AuthorizedKid {
        name: fqdn,
        kid_doc: doc.clone(),
        owner_signature: vec![],
    };

    let signable = auth_kid.signable_bytes(NETWORK_ID);
    use ml_dsa::SignatureEncoding;
    auth_kid.owner_signature = identity_keypair.sign(&signable).to_bytes().to_vec();

    Ok(auth_kid)
}

/// Creates or inherits a Key Identifier (KID) for a given domain name.
///
/// Implements:
/// - **Case 1 (Apex Domain)**: Generates a new ML-DSA-65 keypair and `KidDocument`.
/// - **Case 2 (Subname Inheritance - Default)**: Subdomain inherits parent apex KID from `kids/{apex}.json`.
/// - **Case 3 (Subname Isolation - Opt-In)**: Subdomain generates an isolated keypair when `inherit_subname = false`.
///
/// # Errors
///
/// - Returns [`IdentityError::KidAlreadyExists`] if a KID already exists and `force = false`.
/// - Returns [`IdentityError::KidSigningFailed`] if cryptographic signing fails.
/// - Returns [`IdentityError::Io`] on filesystem failure.
pub fn get_or_create_kid_for_name(
    name: &str,
    inherit_subname: bool,
    force: bool,
) -> Result<GeneratedKid, IdentityError> {
    let fqdn = normalize_name(name);
    let apex = extract_apex_name(&fqdn);
    let is_subname = fqdn != apex;

    let (doc_path, key_path) = get_kid_paths(&fqdn);

    // Case 2: Subname inheritance (Default)
    if is_subname && inherit_subname {
        let (apex_doc_path, _apex_key_path) = get_kid_paths(&apex);
        if apex_doc_path.exists() {
            let doc_data = fs::read_to_string(&apex_doc_path)?;
            let apex_doc: KidDocument = serde_json::from_str(&doc_data)
                .map_err(|e| IdentityError::Json(format!("Malformed apex KID document: {}", e)))?;

            let auth_kid = authorize_kid_document(&fqdn, &apex_doc)?;

            return Ok(GeneratedKid {
                name: fqdn,
                did: apex_doc.kid.as_str().to_string(),
                kid_doc: apex_doc,
                auth_kid,
                doc_path: apex_doc_path,
                key_path: None,
                is_inherited: true,
            });
        }
    }

    // Case 1 & Case 3: Fresh Key & Document Generation
    if doc_path.exists() && !force {
        return Err(IdentityError::KidAlreadyExists(fqdn));
    }

    // 1. Generate new ML-DSA-65 keypair
    let keypair = SigningKey::<MlDsa65>::generate();
    let pub_key_bytes = keypair.verifying_key().to_bytes();
    let pub_key_b64 = b64_url.encode(&pub_key_bytes);

    // 2. Derive deterministic DID string: did:kin:<SHA256(PublicKey)>
    let mut hasher = Sha256::new();
    hasher.update(&pub_key_bytes);
    let did_str = format!("{}{}", DID_PREFIX, hex::encode(hasher.finalize()));

    let kid_did = KineticDid::new(&did_str)
        .map_err(|e| IdentityError::Json(format!("Invalid DID derived: {:?}", e)))?;

    let now_ts = current_network_unix_timestamp();

    let doc = KidDocument {
        doc_type: "kinetic.kid.v1".to_string(),
        kid: kid_did,
        created_at: now_ts,
        controller_keys: vec![ControllerKey {
            id: format!("{}#primary", did_str),
            key_type: "MlDsa65".to_string(),
            public_key: pub_key_b64,
        }],
        manifest: None,
        revocation_keys: vec![],
        deactivated: false,
        signature: None,
    };

    // 3. Self-sign the KidDocument with the new keypair
    let signed_doc = doc
        .sign(&keypair)
        .map_err(|e| IdentityError::KidSigningFailed(format!("{}", e)))?;

    let json_data = serde_json::to_string_pretty(&signed_doc)
        .map_err(|e| IdentityError::Json(format!("{}", e)))?;

    // 4. Securely persist files
    write_private_key_securely(&key_path, &keypair.to_bytes())?;
    write_json_document(&doc_path, &json_data)?;

    // 5. Wrap and sign with master identity.key
    let auth_kid = authorize_kid_document(&fqdn, &signed_doc)?;

    Ok(GeneratedKid {
        name: fqdn,
        did: did_str,
        kid_doc: signed_doc,
        auth_kid,
        doc_path,
        key_path: Some(key_path),
        is_inherited: false,
    })
}

/// Cryptographically rotates the ML-DSA-65 keypair for an existing KID.
///
/// Implements **Case 4 (Key Rotation)**:
/// 1. Generates a fresh ML-DSA-65 keypair.
/// 2. Updates `controller_keys` in the document while preserving the original DID string.
/// 3. Cryptographically signs the updated document with the **OLD key** so the network can verify
///    the handover via [`KidDocument::is_authorized_update`].
/// 4. Atomically replaces the local key and document files.
/// 5. Wraps the new document in [`AuthorizedKid`] signed by the master `identity.key`.
///
/// # Errors
///
/// - Returns [`IdentityError::KidNotFound`] if the document or key does not exist.
/// - Returns [`IdentityError::KidSigningFailed`] if signing fails.
pub fn rotate_name_kid(name: &str) -> Result<RotatedKid, IdentityError> {
    let fqdn = normalize_name(name);
    let (doc_path, key_path) = get_kid_paths(&fqdn);

    if !doc_path.exists() {
        return Err(IdentityError::KidNotFound(format!(
            "KID document not found for {fqdn}"
        )));
    }
    if !key_path.exists() {
        return Err(IdentityError::KidNotFound(format!(
            "KID private key not found for {fqdn}"
        )));
    }

    // 1. Read existing document and key
    let doc_str = fs::read_to_string(&doc_path)?;
    let mut doc: KidDocument = serde_json::from_str(&doc_str)
        .map_err(|e| IdentityError::Json(format!("Corrupted KID document: {}", e)))?;
    let old_key = load_raw_signing_key(&key_path)?;

    // 2. Generate new keypair
    let new_keypair = SigningKey::<MlDsa65>::generate();
    let new_pub_bytes = new_keypair.verifying_key().to_bytes();
    let new_pub_b64 = b64_url.encode(&new_pub_bytes);

    let primary_id = format!("{}#primary", doc.kid);
    doc.controller_keys = vec![ControllerKey {
        id: primary_id,
        key_type: "MlDsa65".to_string(),
        public_key: new_pub_b64,
    }];
    doc.signature = None;

    // 3. Sign the updated document with the OLD key for valid chain of custody
    let signed_doc = doc
        .sign(&old_key)
        .map_err(|e| IdentityError::KidSigningFailed(format!("Rotation signing failed: {}", e)))?;

    let json_data = serde_json::to_string_pretty(&signed_doc)
        .map_err(|e| IdentityError::Json(format!("{}", e)))?;

    // 4. Atomically persist updated files
    write_private_key_securely(&key_path, &new_keypair.to_bytes())?;
    write_json_document(&doc_path, &json_data)?;

    // 5. Wrap in AuthorizedKid signed by identity.key
    let auth_kid = authorize_kid_document(&fqdn, &signed_doc)?;

    Ok(RotatedKid {
        name: fqdn,
        did: signed_doc.kid.as_str().to_string(),
        kid_doc: signed_doc,
        auth_kid,
        doc_path,
        key_path,
    })
}

/// Loads a local KID document for a given name, falling back to parent apex if inherited.
pub fn load_local_kid(name: &str) -> Result<(KidDocument, PathBuf), IdentityError> {
    let fqdn = normalize_name(name);
    let (doc_path, _) = get_kid_paths(&fqdn);

    if doc_path.exists() {
        let content = fs::read_to_string(&doc_path)?;
        let doc: KidDocument = serde_json::from_str(&content)
            .map_err(|e| IdentityError::Json(format!("Malformed KID document: {}", e)))?;
        return Ok((doc, doc_path));
    }

    // Check parent apex domain for subnames
    let apex = extract_apex_name(&fqdn);
    if fqdn != apex {
        let (apex_doc_path, _) = get_kid_paths(&apex);
        if apex_doc_path.exists() {
            let content = fs::read_to_string(&apex_doc_path)?;
            let doc: KidDocument = serde_json::from_str(&content)
                .map_err(|e| IdentityError::Json(format!("Malformed apex KID document: {}", e)))?;
            return Ok((doc, apex_doc_path));
        }
    }

    Err(IdentityError::KidNotFound(fqdn))
}

/// Lists all locally managed domain KIDs from `{base_dir}/kids/`.
pub fn list_local_kids() -> Result<Vec<LocalKidSummary>, IdentityError> {
    let dir = get_kids_dir();
    if !dir.exists() {
        return Ok(vec![]);
    }

    let mut summaries = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(doc) = serde_json::from_str::<KidDocument>(&content) {
                    let stem = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or_default()
                        .to_string();
                    let key_path = path.with_extension("key");
                    summaries.push(LocalKidSummary {
                        name: stem,
                        did: doc.kid.as_str().to_string(),
                        created_at: doc.created_at,
                        doc_path: path,
                        has_key: key_path.exists(),
                        deactivated: doc.deactivated,
                    });
                }
            }
        }
    }

    summaries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(summaries)
}

/// Permanently deactivates and revokes a local KID document.
pub fn revoke_local_kid(name: &str) -> Result<KidDocument, IdentityError> {
    let fqdn = normalize_name(name);
    let (doc_path, key_path) = get_kid_paths(&fqdn);

    if !doc_path.exists() {
        return Err(IdentityError::KidNotFound(format!(
            "Document not found for {fqdn}"
        )));
    }
    if !key_path.exists() {
        return Err(IdentityError::KidNotFound(format!(
            "Key not found for {fqdn}"
        )));
    }

    let content = fs::read_to_string(&doc_path)?;
    let mut doc: KidDocument = serde_json::from_str(&content)
        .map_err(|e| IdentityError::Json(format!("Malformed KID: {}", e)))?;
    let key = load_raw_signing_key(&key_path)?;

    doc.deactivated = true;
    doc.signature = None;

    let signed_doc = doc
        .sign(&key)
        .map_err(|e| IdentityError::KidSigningFailed(format!("{}", e)))?;

    let json_data = serde_json::to_string_pretty(&signed_doc)
        .map_err(|e| IdentityError::Json(format!("{}", e)))?;

    write_json_document(&doc_path, &json_data)?;

    Ok(signed_doc)
}

/// Loads a local `CapabilityManifest` document for a given name if it exists,
/// checking the exact name first and falling back to apex if inherited.
pub fn load_local_manifest(name: &str) -> Result<Option<CapabilityManifest>, IdentityError> {
    let fqdn = normalize_name(name);
    let dir = get_kids_dir();
    let manifest_path = dir.join(format!("{}.manifest.json", fqdn));

    if manifest_path.exists() {
        let content = fs::read_to_string(&manifest_path)?;
        let manifest: CapabilityManifest = serde_json::from_str(&content)
            .map_err(|e| IdentityError::Json(format!("Malformed manifest: {}", e)))?;
        return Ok(Some(manifest));
    }

    let apex = extract_apex_name(&fqdn);
    if fqdn != apex {
        let apex_manifest_path = dir.join(format!("{}.manifest.json", apex));
        if apex_manifest_path.exists() {
            let content = fs::read_to_string(&apex_manifest_path)?;
            let manifest: CapabilityManifest = serde_json::from_str(&content)
                .map_err(|e| IdentityError::Json(format!("Malformed apex manifest: {}", e)))?;
            return Ok(Some(manifest));
        }
    }

    Ok(None)
}

/// Creates, signs with the local KID key, wraps in `AuthorizedManifest`, and persists
/// a `CapabilityManifest` for the given domain name.
pub fn save_and_sign_local_manifest(
    name: &str,
    services: Vec<ServiceEntry>,
) -> Result<(CapabilityManifest, AuthorizedManifest), IdentityError> {
    let fqdn = normalize_name(name);
    let (doc, _) = load_local_kid(&fqdn)?;

    if doc.deactivated {
        return Err(IdentityError::KidSigningFailed(format!(
            "Cannot update manifest for deactivated identity {fqdn}"
        )));
    }

    // Resolve key path (checking specific name key, then fallback to apex key)
    let (_, key_path) = get_kid_paths(&fqdn);
    let effective_key_path = if key_path.exists() {
        key_path
    } else {
        let apex = extract_apex_name(&fqdn);
        let (_, apex_key_path) = get_kid_paths(&apex);
        if apex_key_path.exists() {
            apex_key_path
        } else {
            return Err(IdentityError::KidNotFound(format!(
                "Private key not found for {fqdn} or apex"
            )));
        }
    };

    let signing_key = load_raw_signing_key(&effective_key_path)?;

    // Determine version number (increment if existing manifest found)
    let next_version = match load_local_manifest(&fqdn)? {
        Some(existing) => existing.version.saturating_add(1),
        None => 1,
    };

    let current_time = current_network_unix_timestamp();

    let manifest = CapabilityManifest {
        doc_type: "kinetic.manifest.v1".to_string(),
        kid: doc.kid.clone(),
        version: next_version,
        valid_from: current_time,
        expires_at: None,
        services,
        signature: None,
    };

    let signed_manifest = manifest
        .sign(&signing_key)
        .map_err(|e| IdentityError::KidSigningFailed(format!("Manifest signing failed: {}", e)))?;

    // Persist manifest to kids/{fqdn}.manifest.json
    let dir = get_kids_dir();
    let manifest_path = dir.join(format!("{}.manifest.json", fqdn));
    let json_data = serde_json::to_string_pretty(&signed_manifest)
        .map_err(|e| IdentityError::Json(format!("{}", e)))?;
    write_json_document(&manifest_path, &json_data)?;

    // Wrap in AuthorizedManifest signed by identity.key
    let mut auth_manifest = AuthorizedManifest {
        name: fqdn.clone(),
        manifest: signed_manifest.clone(),
        kid_doc: Some(doc),
        owner_signature: vec![],
    };

    let signable = auth_manifest.signable_bytes(NETWORK_ID);
    let owner_key = load_keypair("identity.key")?;
    use ml_dsa::SignatureEncoding;
    auth_manifest.owner_signature = owner_key.sign(&signable).to_bytes().to_vec();

    Ok((signed_manifest, auth_manifest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_kid_manager_all_lifecycle_cases() {
        let dir = tempdir().unwrap();
        let id_path = dir.path().join("identity.key");
        let seed = [42u8; 32];
        fs::write(&id_path, &seed).unwrap();

        unsafe {
            std::env::set_var(crate::constants::ENV_DATA_DIR, dir.path());
            std::env::set_var(crate::constants::ENV_KEY_PATH, &id_path);
        }

        // 1. Case 1: Apex Domain KID generation
        let apex = get_or_create_kid_for_name("saif.kin", true, false).unwrap();
        assert_eq!(apex.name, "saif.kin");
        assert!(!apex.is_inherited);
        assert!(apex.did.starts_with(DID_PREFIX));
        assert!(apex.doc_path.exists());
        assert!(apex.key_path.as_ref().unwrap().exists());
        assert!(apex.kid_doc.verify().is_ok());
        assert!(apex.kid_doc.verify_genesis().is_ok());

        // Test Overwrite Guard (KIN-IDN-006)
        let err = get_or_create_kid_for_name("saif.kin", true, false).unwrap_err();
        assert_eq!(err.code(), "KIN-IDN-006");

        // Test force overwrite
        let force_res = get_or_create_kid_for_name("saif.kin", true, true).unwrap();
        assert_eq!(force_res.name, "saif.kin");

        // 2. Case 2: Subname inheritance (Default)
        let sub = get_or_create_kid_for_name("blog.saif.kin", true, false).unwrap();
        assert_eq!(sub.name, "blog.saif.kin");
        assert!(sub.is_inherited);
        assert_eq!(sub.did, force_res.did);
        assert!(sub.key_path.is_none());
        assert_eq!(sub.doc_path, force_res.doc_path);

        // 3. Case 3: Subname isolation (Delegation / Opt-out)
        let isolated_sub = get_or_create_kid_for_name("api.saif.kin", false, false).unwrap();
        assert_eq!(isolated_sub.name, "api.saif.kin");
        assert!(!isolated_sub.is_inherited);
        assert_ne!(isolated_sub.did, force_res.did);
        assert!(isolated_sub.key_path.is_some());
        assert_ne!(isolated_sub.doc_path, force_res.doc_path);
        assert!(isolated_sub.kid_doc.verify().is_ok());

        // 4. Case 4: Key Rotation
        let old_pubkey = force_res.kid_doc.controller_keys[0].public_key.clone();
        let rotated = rotate_name_kid("saif.kin").unwrap();
        assert_eq!(rotated.did, force_res.did);
        let new_pubkey = rotated.kid_doc.controller_keys[0].public_key.clone();
        assert_ne!(new_pubkey, old_pubkey);
        // Handover verification succeeds!
        assert!(rotated.kid_doc.is_authorized_update(&force_res.kid_doc));

        // 5. Listing and Revocation
        let kids_list = list_local_kids().unwrap();
        assert!(kids_list.iter().any(|k| k.name == "saif.kin"));
        assert!(kids_list.iter().any(|k| k.name == "api.saif.kin"));

        let revoked = revoke_local_kid("api.saif.kin").unwrap();
        assert!(revoked.deactivated);

        // 6. Capability Manifest lifecycle
        let services = vec![ServiceEntry {
            id: "web".to_string(),
            service_type: "website".to_string(),
            protocol: "https".to_string(),
            endpoint: "https://saif.kin".to_string(),
        }];
        let (saved_manifest, auth_manifest) =
            save_and_sign_local_manifest("saif.kin", services.clone()).unwrap();
        assert_eq!(saved_manifest.version, 1);
        assert_eq!(saved_manifest.services.len(), 1);
        assert!(saved_manifest.verify(&rotated.kid_doc).is_ok());
        assert_eq!(auth_manifest.name, "saif.kin");

        // Load local manifest
        let loaded = load_local_manifest("saif.kin").unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().version, 1);

        // Save again increments version
        let (v2_manifest, _) =
            save_and_sign_local_manifest("saif.kin", services).unwrap();
        assert_eq!(v2_manifest.version, 2);

        // Deactivated identity cannot update manifest
        let deactivated_err =
            save_and_sign_local_manifest("api.saif.kin", vec![]).unwrap_err();
        assert!(matches!(
            deactivated_err,
            IdentityError::KidSigningFailed(_)
        ));

        unsafe {
            std::env::remove_var(crate::constants::ENV_DATA_DIR);
            std::env::remove_var(crate::constants::ENV_KEY_PATH);
        }
    }
}
