//! Canonical Kinetic Identity Document (KID) Management Engine for the Kinetic Network.
//!
//! This module provides a single source of truth for creating, inheriting, loading,
//! listing, and cryptographically rotating post-quantum Kinetic Identity Documents (KIDs)
//! and their underlying ML-DSA-65 keys across the CLI, Daemon, and Network layers.
//!
//! ## Core Invariants & The 4 Identity Cases
//!
//! 1. **Case 1 (New Apex Name)**: Generates a new dedicated ML-DSA-65 keypair (`kids/{name}.key`)
//!    and a unique `Document` (`did:kin:<SHA256(PublicKey)>`). Overwrites are rejected unless `force = true`.
//! 2. **Case 2 (Subname Inheritance - Default)**: Subnames (e.g. `blog.saif.kin`) inherit their parent's
//!    apex KID (`did:kin:...`) from `kids/{apex}.json`, avoiding key sprawl.
//! 3. **Case 3 (Subname Isolation - Opt-In)**: Subnames generate an isolated, independent KID and keypair
//!    for delegated or untrusted sub-services (`inherit_subname = false`).
//! 4. **Case 4 (Cryptographic Key Rotation)**: Rotates the ML-DSA-65 controller key of a name while keeping
//!    the DID string constant. The update is cryptographically signed by the *previous* key to satisfy
//!    DHT verification rules (`is_authorized`).
//!
//! All KID operations wrap the resulting document in an [`AuthorizedKid`] container signed by the node's
//! master `identity.key` (the name owner).

#![cfg(not(target_arch = "wasm32"))]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64_url};

use serde::{Deserialize, Serialize};

use crate::identity::load_keypair;
use kinetic_core::constants::DID_PREFIX;
use kinetic_core::error::IdentityError;
use kinetic_core::types::names::{extract_apex_name, normalize_name};
use kinetic_kid::Did;
use kinetic_kid::document::{ControllerKey, Document};
use kinetic_kid::manifest::{Manifest, Service};
use kinetic_types::identity::{AuthorizedKid, AuthorizedManifest};

/// Metadata and payloads resulting from a generated or inherited KID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedKid {
    /// Fully qualified name this KID is bound to (e.g. "saif.kin" or "blog.saif.kin").
    pub name: String,
    /// The W3C DID string (e.g. "did:kin:<hash>").
    pub did: String,
    /// The inner signed [`Document`].
    pub kid_doc: Document,
    /// The outer [`AuthorizedKid`] envelope signed by the master `identity.key`.
    pub auth_kid: AuthorizedKid,
    /// Path to the KID JSON document file on disk.
    pub doc_path: PathBuf,
    /// Path to the private key file on disk (`None` if inherited from apex).
    pub key_path: Option<PathBuf>,
    /// Whether this KID was inherited from an apex name.
    pub is_inherited: bool,
}

/// Metadata and payloads resulting from a cryptographically rotated KID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotatedKid {
    /// Fully qualified name whose KID was rotated.
    pub name: String,
    /// The unchanged DID string.
    pub did: String,
    /// The newly rotated and signed [`Document`].
    pub kid_doc: Document,
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
pub fn unix_time() -> kinetic_types::clock::UTime {
    use kinetic_core::types::clock::KynNetworkExt;
    kinetic_types::clock::Kyn::now_local().to_network_utime()
}

/// Resolves the filesystem paths for a name's KID document and private key.
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
fn load_raw_signing_key(
    path: &Path,
) -> Result<kinetic_primitives::keys::KineticKeypair, IdentityError> {
    if !path.exists() {
        return Err(IdentityError::KidPrivateKeyNotFound(
            path.to_string_lossy().to_string(),
        ));
    }
    let bytes = fs::read(path)?;
    kinetic_primitives::keys::KineticKeypair::from_slice(&bytes).map_err(|_| {
        IdentityError::CorruptedIdentityFile(format!("Invalid key bytes in {:?}", path))
    })
}

/// Wraps a [`Document`] in an [`AuthorizedKid`] envelope and signs it with the master `identity.key`.
pub fn authorize_kid_document(
    name: &str,
    doc: &Document,
    master_key_path: &Path,
) -> Result<AuthorizedKid, IdentityError> {
    let fqdn = normalize_name(name);
    let identity_keypair = load_keypair(master_key_path)?;

    let mut auth_kid = AuthorizedKid {
        name: fqdn,
        kid_doc: doc.clone(),
        owner_signature: vec![],
    };

    let signable = auth_kid.signable_bytes(kinetic_core::constants::NETWORK_SALT);
    auth_kid.owner_signature = identity_keypair.sign(&signable);

    Ok(auth_kid)
}

/// Creates or inherits a Kinetic Identity Document (KID) for a given name.
///
/// Implements:
/// - **Case 1 (Apex Name)**: Generates a new ML-DSA-65 keypair and `Document`.
/// - **Case 2 (Subname Inheritance - Default)**: Subname inherits parent apex KID from `kids/{apex}.json`.
/// - **Case 3 (Subname Isolation - Opt-In)**: Subname generates an isolated keypair when `inherit_subname = false`.
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
    current_kyn: kinetic_types::clock::Kyn,
    master_key_path: &Path,
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
            let apex_doc: Document = serde_json::from_str(&doc_data)
                .map_err(|e| IdentityError::MalformedApexDocument(format!("{}", e)))?;

            let auth_kid = authorize_kid_document(&fqdn, &apex_doc, master_key_path)?;

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
    let keypair = kinetic_primitives::keys::KineticKeypair::generate();
    let pub_key_bytes = keypair.pubkey_bytes();
    let pub_key_b64 = b64_url.encode(&pub_key_bytes);

    // 2. Derive deterministic DID string: did:kin:<SHA256(PublicKey)>
    let hash = kinetic_primitives::sha256_hash(&pub_key_bytes);
    let did_str = format!("{}{}", DID_PREFIX, hex::encode(hash));

    let kid_did = Did::new(&did_str)
        .map_err(|e| IdentityError::InvalidDid(format!("Invalid DID derived: {:?}", e)))?;

    use kinetic_core::types::clock::KynNetworkExt;
    let now_ts = current_kyn.to_network_utime().0;

    let doc = Document {
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

    // 3. Self-sign the Document with the new keypair
    let signed_doc = doc
        .sign(&keypair)
        .map_err(|e| IdentityError::KidSigningFailed(format!("{}", e)))?;

    let json_data = serde_json::to_string_pretty(&signed_doc)
        .map_err(|e| IdentityError::SerializationFailed(format!("{}", e)))?;

    // 4. Securely persist files
    write_private_key_securely(&key_path, &keypair.to_bytes())?;
    write_json_document(&doc_path, &json_data)?;

    // 5. Wrap and sign with master identity.key
    let auth_kid = authorize_kid_document(&fqdn, &signed_doc, master_key_path)?;

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
///    the handover via [`Document::is_authorized`].
/// 4. Atomically replaces the local key and document files.
/// 5. Wraps the new document in [`AuthorizedKid`] signed by the master `identity.key`.
///
/// # Errors
///
/// - Returns [`IdentityError::KidNotFound`] if the document or key does not exist.
/// - Returns [`IdentityError::KidSigningFailed`] if signing fails.
pub fn rotate_name_kid(name: &str, master_key_path: &Path) -> Result<RotatedKid, IdentityError> {
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
    let mut doc: Document = serde_json::from_str(&doc_str)
        .map_err(|e| IdentityError::MalformedDocument(format!("{}", e)))?;
    let old_key = load_raw_signing_key(&key_path)?;

    // 2. Generate new keypair
    let new_keypair = kinetic_primitives::keys::KineticKeypair::generate();
    let new_pub_bytes = new_keypair.pubkey_bytes();
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
        .map_err(|e| IdentityError::SerializationFailed(format!("{}", e)))?;

    // 4. Atomically persist updated files
    write_private_key_securely(&key_path, &new_keypair.to_bytes())?;
    write_json_document(&doc_path, &json_data)?;

    // 5. Wrap in AuthorizedKid signed by identity.key
    let auth_kid = authorize_kid_document(&fqdn, &signed_doc, master_key_path)?;

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
pub fn load_local_kid(name: &str) -> Result<(Document, PathBuf), IdentityError> {
    let fqdn = normalize_name(name);
    let (doc_path, _) = get_kid_paths(&fqdn);

    if doc_path.exists() {
        let content = fs::read_to_string(&doc_path)?;
        let doc: Document = serde_json::from_str(&content)
            .map_err(|e| IdentityError::MalformedDocument(format!("{}", e)))?;
        return Ok((doc, doc_path));
    }

    // Check parent apex name for subnames
    let apex = extract_apex_name(&fqdn);
    if fqdn != apex {
        let (apex_doc_path, _) = get_kid_paths(&apex);
        if apex_doc_path.exists() {
            let content = fs::read_to_string(&apex_doc_path)?;
            let doc: Document = serde_json::from_str(&content)
                .map_err(|e| IdentityError::MalformedApexDocument(format!("{}", e)))?;
            return Ok((doc, apex_doc_path));
        }
    }

    Err(IdentityError::KidNotFound(fqdn))
}

/// Lists all locally managed name KIDs from `{base_dir}/kids/`.
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
                if let Ok(doc) = serde_json::from_str::<Document>(&content) {
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
pub fn revoke_local_kid(name: &str) -> Result<Document, IdentityError> {
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
    let mut doc: Document = serde_json::from_str(&content)
        .map_err(|e| IdentityError::MalformedDocument(format!("{}", e)))?;
    let key = load_raw_signing_key(&key_path)?;

    doc.deactivated = true;
    doc.signature = None;

    let signed_doc = doc
        .sign(&key)
        .map_err(|e| IdentityError::KidSigningFailed(format!("{}", e)))?;

    let json_data = serde_json::to_string_pretty(&signed_doc)
        .map_err(|e| IdentityError::SerializationFailed(format!("{}", e)))?;

    write_json_document(&doc_path, &json_data)?;

    Ok(signed_doc)
}

/// Loads a local `Manifest` document for a given name if it exists,
/// checking the exact name first and falling back to apex if inherited.
pub fn load_local_manifest(name: &str) -> Result<Option<Manifest>, IdentityError> {
    let fqdn = normalize_name(name);
    let dir = get_kids_dir();
    let manifest_path = dir.join(format!("{}.manifest.json", fqdn));

    if manifest_path.exists() {
        let content = fs::read_to_string(&manifest_path)?;
        let manifest: Manifest = serde_json::from_str(&content)
            .map_err(|e| IdentityError::MalformedManifest(format!("{}", e)))?;
        return Ok(Some(manifest));
    }

    let apex = extract_apex_name(&fqdn);
    if fqdn != apex {
        let apex_manifest_path = dir.join(format!("{}.manifest.json", apex));
        if apex_manifest_path.exists() {
            let content = fs::read_to_string(&apex_manifest_path)?;
            let manifest: Manifest = serde_json::from_str(&content)
                .map_err(|e| IdentityError::MalformedManifest(format!("{}", e)))?;
            return Ok(Some(manifest));
        }
    }

    Ok(None)
}

/// Creates, signs with the local KID key, wraps in `AuthorizedManifest`, and persists
/// a `Manifest` for the given name.
pub fn save_and_sign_local_manifest(
    name: &str,
    services: Vec<Service>,
    current_kyn: kinetic_types::clock::Kyn,
    master_key_path: &Path,
) -> Result<(Manifest, AuthorizedManifest), IdentityError> {
    let fqdn = normalize_name(name);
    let (doc, _) = load_local_kid(&fqdn)?;

    if doc.deactivated {
        return Err(IdentityError::KidDeactivated(fqdn.to_string()));
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

    use kinetic_core::types::clock::KynNetworkExt;
    let current_time = current_kyn.to_network_utime().0;

    let manifest = Manifest {
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
        .map_err(|e| IdentityError::ManifestSigningFailed(format!("{}", e)))?;

    // Persist manifest to kids/{fqdn}.manifest.json
    let dir = get_kids_dir();
    let manifest_path = dir.join(format!("{}.manifest.json", fqdn));
    let json_data = serde_json::to_string_pretty(&signed_manifest)
        .map_err(|e| IdentityError::SerializationFailed(format!("{}", e)))?;
    write_json_document(&manifest_path, &json_data)?;

    // Wrap in AuthorizedManifest signed by identity.key
    let mut auth_manifest = AuthorizedManifest {
        name: fqdn.clone(),
        manifest: signed_manifest.clone(),
        kid_doc: Some(doc),
        owner_signature: vec![],
    };

    let signable = auth_manifest.signable_bytes(kinetic_core::constants::NETWORK_SALT);
    let owner_key = load_keypair(master_key_path)?;
    auth_manifest.owner_signature = owner_key.sign(&signable);

    Ok((signed_manifest, auth_manifest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kinetic_core::types::{Kyn, KynNetworkExt};
    use lazy_static::lazy_static;
    use std::sync::Mutex;
    use tempfile::tempdir;

    lazy_static! {
        // Global lock to prevent environment variable race conditions during parallel tests
        static ref ENV_LOCK: Mutex<()> = Mutex::new(());
    }

    struct TestEnv {
        _dir: tempfile::TempDir,
        master_key_path: PathBuf,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl TestEnv {
        fn new(seed: [u8; 32]) -> Self {
            let guard = ENV_LOCK.lock().unwrap();
            let dir = tempdir().unwrap();
            let id_path = dir.path().join("identity.key");
            std::fs::write(&id_path, seed).unwrap();

            // Set data dir only (identity is passed explicitly now)
            unsafe {
                std::env::set_var(kinetic_core::constants::ENV_DATA_DIR, dir.path());
            }

            Self {
                _dir: dir,
                master_key_path: id_path,
                _guard: guard,
            }
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var(kinetic_core::constants::ENV_DATA_DIR);
            }
        }
    }

    #[test]
    fn test_kid_generation_and_overwrite_guards() {
        let env = TestEnv::new([42u8; 32]);

        // 1. Apex Name KID generation
        let apex =
            get_or_create_kid_for_name("saif.kin", true, false, Kyn(100), &env.master_key_path).unwrap();
        assert_eq!(apex.name, "saif.kin");
        assert!(!apex.is_inherited);
        assert!(apex.did.starts_with(DID_PREFIX));
        assert!(apex.doc_path.exists());
        assert!(apex.key_path.as_ref().unwrap().exists());
        assert!(apex.kid_doc.verify().is_ok());
        assert!(apex.kid_doc.verify_genesis().is_ok());

        // Test Overwrite Guard (KIN-IDN-006)
        let err = get_or_create_kid_for_name("saif.kin", true, false, Kyn(100), &env.master_key_path)
            .unwrap_err();
        assert_eq!(err.code(), "KIN-IDN-006");

        // Test force overwrite
        let force_res =
            get_or_create_kid_for_name("saif.kin", true, true, Kyn(100), &env.master_key_path).unwrap();
        assert_eq!(force_res.name, "saif.kin");
    }

    #[test]
    fn test_kid_subname_inheritance() {
        let env = TestEnv::new([42u8; 32]);
        let apex =
            get_or_create_kid_for_name("saif.kin", true, false, Kyn(100), &env.master_key_path).unwrap();

        let sub =
            get_or_create_kid_for_name("blog.saif.kin", true, false, Kyn(100), &env.master_key_path)
                .unwrap();
        assert_eq!(sub.name, "blog.saif.kin");
        assert!(sub.is_inherited);
        assert_eq!(sub.did, apex.did);
        assert!(sub.key_path.is_none());
        assert_eq!(sub.doc_path, apex.doc_path);
    }

    #[test]
    fn test_kid_subname_isolation() {
        let env = TestEnv::new([42u8; 32]);
        let apex =
            get_or_create_kid_for_name("saif.kin", true, false, Kyn(100), &env.master_key_path).unwrap();

        let isolated_sub =
            get_or_create_kid_for_name("api.saif.kin", false, false, Kyn(100), &env.master_key_path)
                .unwrap();
        assert_eq!(isolated_sub.name, "api.saif.kin");
        assert!(!isolated_sub.is_inherited);
        assert_ne!(isolated_sub.did, apex.did);
        assert!(isolated_sub.key_path.is_some());
        assert_ne!(isolated_sub.doc_path, apex.doc_path);
        assert!(isolated_sub.kid_doc.verify().is_ok());
    }

    #[test]
    fn test_kid_rotation_handover() {
        let env = TestEnv::new([42u8; 32]);
        let apex =
            get_or_create_kid_for_name("saif.kin", true, false, Kyn(100), &env.master_key_path).unwrap();
        let old_pubkey = apex.kid_doc.controller_keys[0].public_key.clone();

        let rotated = rotate_name_kid("saif.kin", &env.master_key_path).unwrap();
        assert_eq!(rotated.did, apex.did);
        let new_pubkey = rotated.kid_doc.controller_keys[0].public_key.clone();
        assert_ne!(new_pubkey, old_pubkey);

        // Handover verification succeeds!
        assert!(rotated.kid_doc.is_authorized(&apex.kid_doc));
    }

    #[test]
    fn test_manifest_version_increments() {
        let env = TestEnv::new([42u8; 32]);
        let apex =
            get_or_create_kid_for_name("saif.kin", true, false, Kyn(100), &env.master_key_path).unwrap();

        let services = vec![Service {
            id: "web".to_string(),
            service_type: "website".to_string(),
            protocol: "https".to_string(),
            endpoint: "https://saif.kin".to_string(),
        }];

        let (saved_manifest, auth_manifest) =
            save_and_sign_local_manifest("saif.kin", services.clone(), Kyn(100), &env.master_key_path)
                .unwrap();
        assert_eq!(saved_manifest.version, 1);
        assert_eq!(saved_manifest.services.len(), 1);
        assert!(saved_manifest.verify_at_time(&apex.kid_doc, Kyn(100).to_network_utime().0).is_ok());
        assert_eq!(auth_manifest.name, "saif.kin");

        let loaded = load_local_manifest("saif.kin").unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().version, 1);

        let (v2_manifest, _) =
            save_and_sign_local_manifest("saif.kin", services, Kyn(100), &env.master_key_path).unwrap();
        assert_eq!(v2_manifest.version, 2);
    }

    #[test]
    fn test_invalid_fqdn_doesnt_crash() {
        let env = TestEnv::new([42u8; 32]);
        let _ = get_or_create_kid_for_name("invalid..name", true, false, Kyn(100), &env.master_key_path);
    }

    #[test]
    fn test_rotate_inherited_subname_fails() {
        let env = TestEnv::new([42u8; 32]);
        let _ =
            get_or_create_kid_for_name("saif.kin", true, false, Kyn(100), &env.master_key_path).unwrap();
        let _ = get_or_create_kid_for_name("blog.saif.kin", true, false, Kyn(100), &env.master_key_path)
            .unwrap();

        let err = rotate_name_kid("blog.saif.kin", &env.master_key_path).unwrap_err();
        assert!(
            matches!(err, IdentityError::KidNotFound(_)),
            "Err was {:?}",
            err
        );
    }

    #[test]
    fn test_revoked_kid_cannot_sign_manifest() {
        let env = TestEnv::new([42u8; 32]);
        let _ = get_or_create_kid_for_name("api.saif.kin", false, false, Kyn(100), &env.master_key_path)
            .unwrap();

        let revoked = revoke_local_kid("api.saif.kin").unwrap();
        assert!(revoked.deactivated);

        let deactivated_err =
            save_and_sign_local_manifest("api.saif.kin", vec![], Kyn(100), &env.master_key_path)
                .unwrap_err();
        assert!(matches!(deactivated_err, IdentityError::KidDeactivated(_)));
    }

    #[test]
    fn test_missing_master_identity() {
        let _guard = ENV_LOCK.lock().unwrap();
        let env = tempdir().unwrap();
        unsafe {
            std::env::set_var(kinetic_core::constants::ENV_DATA_DIR, env.path());
        }
        let missing_path = env.path().join("missing.key");

        let err =
            get_or_create_kid_for_name("saif.kin", true, false, Kyn(100), &missing_path).unwrap_err();
        assert!(matches!(err, IdentityError::IdentityNotFound(_)));

        unsafe {
            std::env::remove_var(kinetic_core::constants::ENV_DATA_DIR);
        }
    }

    #[test]
    fn test_corrupted_kid_document() {
        let env = TestEnv::new([42u8; 32]);
        let apex =
            get_or_create_kid_for_name("saif.kin", true, false, Kyn(100), &env.master_key_path).unwrap();

        // Corrupt the json file
        std::fs::write(&apex.doc_path, "not valid json").unwrap();

        let err = load_local_kid("saif.kin").unwrap_err();
        assert!(matches!(err, IdentityError::MalformedDocument(_)));
    }
}
