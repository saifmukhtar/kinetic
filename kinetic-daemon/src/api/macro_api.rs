//! HTTP REST API endpoints and background task workers for VDF generation workflows.
//!
//! ## Layer 8 Architecture: Asynchronous UI Task Management
//! Because generating a Verifiable Delay Function (VDF) for a Standard Domain Registration
//! takes significant wall-clock time (potentially hours depending on the difficulty), the
//! UI cannot simply block on an HTTP request.
//!
//! This module implements the **Macro API Pattern**:
//! 1. The user's Desktop UI sends a POST request to initiate a heavy cryptographic workflow.
//! 2. The endpoint immediately spins up a detached `tokio::spawn` worker to execute the math.
//! 3. The endpoint returns a unique `task_id` to the UI instantly (HTTP 202 Accepted).
//! 4. The detached worker computes the VDF in the background, updating a thread-safe `Arc<Mutex>`
//!    status map at each cryptographic milestone.
//! 5. The UI periodically polls `/api/v1/macro/tasks/{task_id}` to display a real-time progress bar.

use super::*;
use axum::{
    Json,
    extract::{Extension, Path, State},
};

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Payload for renewing a registered Kinetic name via VDF.
#[derive(Deserialize)]
pub struct NameRenewRequest {
    /// The name to renew.
    pub name: String,
    /// Optional overridden iteration count.
    pub iterations: Option<u64>,
}

/// Payload for registering a new Kinetic name via VDF.
#[derive(Deserialize)]
pub struct VdfRegisterRequest {
    /// The name to register.
    pub name: String,
    /// Optional overridden iteration count.
    pub iterations: Option<u64>,
}

/// Handles API requests to initiate a backgkyn VDF registration task.
/// Ensures that only one VDF task is actively running.
///
/// # Errors
///
/// Returns an error if a VDF task is already running.
pub async fn handle_macro_register_name(
    Extension(role): Extension<Role>,
    State(state): State<ApiState>,
    Json(req): Json<VdfRegisterRequest>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_vdf() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }
    let fqdn = kinetic_core::types::normalize_name(&req.name);
    kinetic_core::types::is_valid_apex_name(&fqdn)?;

    const MAX_USER_ITERATIONS: u64 = 10_000_000;
    if req.iterations.unwrap_or(0) > MAX_USER_ITERATIONS {
        return Err(crate::api::error::AppError(
            kinetic_core::error::VdfError::MaxIterationsExceeded.into(),
        ));
    }
    let task_id = uuid::Uuid::new_v4().to_string();

    // Store initial task state, ensuring only 1 is active
    {
        let mut tasks = state.vdf_tasks.lock().unwrap_or_else(|e| e.into_inner());

        let active_tasks = tasks
            .values()
            .filter(|t| t.progress < 100 && t.error.is_none())
            .count();
        if active_tasks >= 1 {
            return Err(kinetic_core::error::RegistrationError::AlreadyInProgress {
                name: fqdn.clone(),
            }
            .into());
        }

        tasks.retain(|_, t| t.progress < 100 && t.error.is_none());

        if tasks.len() >= 50 {
            return Err(crate::api::error::AppError(
                kinetic_core::error::VdfError::TooManyTasks.into(),
            ));
        }

        tasks.insert(
            task_id.clone(),
            VdfTaskStatus {
                status: "Initializing".to_string(),
                iterations: req.iterations.unwrap_or(4_194_304), // Default lower for testing in UI
                progress: 0,
                error: None,
            },
        );
    }

    // Spawn blocking backgkyn task
    let tasks_clone = state.vdf_tasks.clone();
    let network_clone = state.network.clone();
    let storage_clone = state.storage.clone();
    let task_id_clone = task_id.clone();
    let iterations = req.iterations.unwrap_or(4_194_304);

    tokio::spawn(async move {
        // Step 1: KYN Time Oracle
        update_task_status(&tasks_clone, &task_id_clone, "Fetching Network Beacon", 10);
        let kyn_provider: std::sync::Arc<dyn kinetic_core::traits::KynProvider> =
            std::sync::Arc::new(
                kinetic_network::client::beacon::BeaconProvider::new(Some(
                    storage_clone.clone(),
                )),
            );
        let raw_kyn = match kyn_provider.load_cached() {
            Ok(data) => data,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Beacon error: {}", e),
                );
                return;
            }
        };

        // Step 2: Commitment — generate privately now; broadcast AFTER the VDF proof exists.
        //
        // Option B (C-1 fix): The old flow broadcast the commitment first, then computed the VDF.
        // For any name whose VDF takes longer than the commitment prune window the reveal always
        // arrived to a dead commitment. By deferring the broadcast until the proof is in hand the
        // commitment is always at most ~32 seconds old when the reveal lands — fixing C-1 for
        // every name length, including 2-4 char names whose VDFs take days to months.
        //
        // Anti-front-running is fully preserved: the commitment hash is
        // SHA-256(name‖salt‖randomness‖pubkey) — opaque to any observer during the 32-second
        // window before the reveal appears.
        update_task_status(&tasks_clone, &task_id_clone, "Generating Commitment", 20);
        let identity_path = kinetic_local::config::base_dir().join("identity.key");
        let keypair = match kinetic_local::identity::load_keypair(&identity_path) {
            Ok(k) => k,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Keypair error: {}", e),
                );
                return;
            }
        };
        let pubkey = keypair.to_pubkey().0;
        let mut salt = [0u8; 32];
        if let Err(e) = getrandom::fill(&mut salt) {
            update_task_error(
                &tasks_clone,
                &task_id_clone,
                format!("Failed to generate secure random salt: {}", e),
            );
            return;
        }
        let sig_bytes = match hex::decode(&raw_kyn.signature) {
            Ok(b) => b,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Failed to decode Beacon signature: {}", e),
                );
                return;
            }
        };

        let challenge = kinetic_core::types::Commitment::derive(
            kinetic_core::constants::NETWORK_SALT,
            &fqdn,
            &salt,
            &sig_bytes,
            &kinetic_primitives::keypairs::IdentityPubKey(pubkey.to_vec()),
        );

        // Step 3: VDF Evaluation (Blocking)
        update_task_status(
            &tasks_clone,
            &task_id_clone,
            "Computing VDF... (this may take a while)",
            30,
        );
        let required_iters =
            kinetic_core::consensus_math::ConsensusParams::default().iterations(&fqdn);
        let actual_iterations = std::cmp::max(iterations, required_iters);

        let vdf_engine = kinetic_vdf::RsaVdfEngine::new();
        let challenge_clone = challenge.clone();

        let permit_res = state.vdf_semaphore.clone().acquire_owned().await;
        if permit_res.is_err() {
            update_task_error(&tasks_clone, &task_id_clone, "VDF Semaphore closed".into());
            return;
        }
        let permit = permit_res.unwrap();

        // Spawn blocking to not starve tokio executor
        let proof = match tokio::task::spawn_blocking(move || {
            use kinetic_core::traits::VdfEngine;
            vdf_engine.evaluate(&challenge_clone, actual_iterations)
        })
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("VDF engine error: {}", e),
                );
                return;
            }
            Err(e) => {
                update_task_error(&tasks_clone, &task_id_clone, format!("Task panic: {}", e));
                return;
            }
        };

        drop(permit);

        // Broadcast commitment now that the proof exists (Option B / C-1 fix).
        // Commitment age will be ~32 s when the reveal lands — well within any prune window.
        update_task_status(&tasks_clone, &task_id_clone, "Broadcasting Commitment", 85);
        let commit_bytes = match serde_json::to_vec(&challenge) {
            Ok(b) => b,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Commitment serialization error: {}", e),
                );
                return;
            }
        };
        if let Err(e) = network_clone
            .publish_redundant_payload(&fqdn, commit_bytes)
            .await
        {
            update_task_error(
                &tasks_clone,
                &task_id_clone,
                format!("DHT Commit Error: {}", e),
            );
            return;
        }

        // Wait enough kyns to satisfy the commit_age rule in verify_reveal.
        let wait_secs = kinetic_core::constants::CONSENSUS_MINIMUM_COMMIT_AGE_KYNS + 2;
        update_task_status(
            &tasks_clone,
            &task_id_clone,
            &format!("Maturing commitment ({} s)...", wait_secs),
            88,
        );
        tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;

        update_task_status(&tasks_clone, &task_id_clone, "Publishing Registration", 90);

        // Generate or fetch KID for the user to attach to the new zone
        update_task_status(&tasks_clone, &task_id_clone, "Injecting Identity (KID)", 92);
        let current_kyn = {
            let kyn_provider = kinetic_network::client::beacon::BeaconProvider::new(Some(
                storage_clone.clone(),
            ));
            use kinetic_core::traits::KynProvider;

            match kyn_provider.load_cached() {
                Ok(kyn) => kyn.kyn(),
                Err(_) => kinetic_local::time::now_local(kinetic_core::constants::BEACON_GENESIS).0,
            }
        };
        let current_kyn = kinetic_kyn::types::Kyn(current_kyn);
        let identity_path = kinetic_local::config::base_dir().join("identity.key");

        let kid_id = match kinetic_local::kid_manager::get_or_create_kid_for_name(
            &fqdn,
            true,
            false,
            current_kyn,
            &identity_path,
        ) {
            Ok(res) => res.did,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Failed to generate identity: {}", e),
                );
                return;
            }
        };

        // Construct Reveal and Zone with KID injected
        let mut records = HashMap::new();
        records.insert(
            "@".to_string(),
            vec![kinetic_core::types::NrsRecord::KID(kid_id)],
        );
        let zone = kinetic_core::types::NrsZone { records };
        let payload = match serde_json::to_vec(&zone) {
            Ok(b) => b,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Serialization failed in VDF task: {}", e),
                );
                tracing::error!(
                    error = ?kinetic_core::error::NrsError::ParseError(e),
                    "Serialization failed in VDF task"
                );
                return;
            }
        };

        let mut reveal = kinetic_core::types::Reveal {
            protocol_version: 1,
            name: fqdn.clone(),
            payload,
            salt,
            kyn: kinetic_kyn::types::TargetKyn::from(raw_kyn.kyn()),
            beacon_signature: raw_kyn.signature.clone(),
            iterations: actual_iterations,
            vdf_proof: kinetic_core::types::VdfProof {
                proof_bytes: proof.proof_bytes,
            },
            pubkey: kinetic_primitives::keypairs::IdentityPubKey(pubkey.to_vec()),
            identity_signature: kinetic_primitives::keypairs::IdentitySignature(vec![]),
            authorization: None,
            previous_proof: None,
        };

        let signable = reveal.signable_bytes(kinetic_core::constants::NETWORK_SALT);
        reveal.identity_signature = keypair.sign(&signable);

        // Publish to Network
        let reveal_bytes = match serde_json::to_vec(&reveal) {
            Ok(b) => b,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Serialization failed in VDF task: {}", e),
                );
                tracing::error!(
                    error = ?kinetic_core::error::NrsError::ParseError(e),
                    "Serialization failed in VDF task"
                );
                return;
            }
        };
        if let Err(e) = network_clone
            .publish_redundant_payload(&fqdn, reveal_bytes)
            .await
        {
            update_task_error(
                &tasks_clone,
                &task_id_clone,
                format!("DHT Publish Error: {}", e),
            );
            return;
        }

        // Save to internal storage so Dashboard can see it
        let fqdn_clone = fqdn.clone();
        let _lock = crate::api::OWNED_NAMES_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut owned = Vec::new();
        if let Ok(Some(bytes)) = storage_clone.get(kinetic_core::constants::DB_PREFIX_OWNED_NAMES)
            && let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes)
        {
            owned = names;
        }
        if !owned.contains(&fqdn_clone) {
            owned.push(fqdn_clone.clone());
            if owned.len() > 10_000 {
                let skip_count = owned.len() - 10_000;
                owned = owned.into_iter().skip(skip_count).collect();
            }
            if let Ok(b) = serde_json::to_vec(&owned) {
                let _ = storage_clone.put(kinetic_core::constants::DB_PREFIX_OWNED_NAMES, &b);
            }
        }
        drop(_lock);

        // Save default zone file
        let zones_dir = kinetic_local::config::zones_dir().join("config");
        let _ = std::fs::create_dir_all(&zones_dir);
        let path = zones_dir.join(format!("{}.json", fqdn));
        if let Ok(s) = serde_json::to_string_pretty(&zone)
            && let Err(e) = std::fs::write(&path, s)
        {
            tracing::warn!(
                error = ?kinetic_core::error::StorageError::WriteFailed(e.to_string()),
                "Failed to write zone file"
            );
        }

        update_task_status(&tasks_clone, &task_id_clone, "Complete", 100);
    });

    Ok(Json(serde_json::json!({
        "task_id": task_id,
        "message": "VDF generation started"
    })))
}

/// Handles API requests to renew a Kinetic name via a new VDF proof, leveraging an existing reveal.
///
/// # Errors
///
/// Returns an error if there are issues finding the previous reveal or scheduling the VDF task.
pub async fn handle_macro_renew_name(
    Extension(role): Extension<Role>,
    State(state): State<ApiState>,
    Json(req): Json<NameRenewRequest>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_vdf() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }
    let fqdn = kinetic_core::types::normalize_name(&req.name);
    kinetic_core::types::is_valid_apex_name(&fqdn)?;

    const MAX_USER_ITERATIONS: u64 = 10_000_000;
    if req.iterations.unwrap_or(0) > MAX_USER_ITERATIONS {
        return Err(crate::api::error::AppError(
            kinetic_core::error::VdfError::MaxIterationsExceeded.into(),
        ));
    }
    let mut tasks = state.vdf_tasks.lock().unwrap_or_else(|e| e.into_inner());

    tasks.retain(|_, t| t.progress < 100 && t.error.is_none());
    if tasks.len() >= 50 {
        return Err(crate::api::error::AppError(
            kinetic_core::error::VdfError::TooManyTasks.into(),
        ));
    }

    let task_id = uuid::Uuid::new_v4().to_string();
    let initial_task = VdfTaskStatus {
        status: "Starting Renewal...".into(),
        progress: 0,
        error: None,
        iterations: req.iterations.unwrap_or(4_194_304),
    };
    tasks.insert(task_id.clone(), initial_task.clone());
    drop(tasks);

    let tasks_clone = state.vdf_tasks.clone();
    let network_clone = state.network.clone();
    let storage_clone = state.storage.clone();
    let task_id_clone = task_id.clone();
    let iterations = req.iterations.unwrap_or(4_194_304);

    tokio::spawn(async move {
        // Step 1: Read previous Reveal from database storage
        update_task_status(&tasks_clone, &task_id_clone, "Loading previous reveal", 5);
        let local_reveal_key = format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, fqdn);
        let old_reveal_bytes = match storage_clone.get(local_reveal_key.as_bytes()) {
            Ok(Some(b)) => b,
            _ => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Name {} not found locally", fqdn),
                );
                return;
            }
        };
        let old_record: kinetic_core::types::NameRecord = match serde_json::from_slice(
            &old_reveal_bytes,
        ) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    error = ?kinetic_core::error::StorageError::DeserializationFailed(e.to_string()),
                    "{}",
                    kinetic_core::error::StorageError::DeserializationFailed(e.to_string()).user_message()
                );
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Local Reveal corrupted: {}", e),
                );
                return;
            }
        };
        let kinetic_core::types::NameRecord::Standard(old_reveal) = old_record;

        // Step 2: KYN Time Oracle
        update_task_status(&tasks_clone, &task_id_clone, "Fetching Network Beacon", 10);
        let kyn_provider: std::sync::Arc<dyn kinetic_core::traits::KynProvider> =
            std::sync::Arc::new(
                kinetic_network::client::beacon::BeaconProvider::new(Some(
                    storage_clone.clone(),
                )),
            );
        let raw_kyn = match kyn_provider.load_cached() {
            Ok(d) => d,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Beacon error: {}", e),
                );
                return;
            }
        };

        // Step 3: Commitment — generate privately; broadcast AFTER VDF (Option B / C-1 fix).
        update_task_status(&tasks_clone, &task_id_clone, "Generating Commitment", 20);
        let identity_path = kinetic_local::config::base_dir().join("identity.key");
        let keypair = match kinetic_local::identity::load_keypair(&identity_path) {
            Ok(k) => k,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Keypair error: {}", e),
                );
                return;
            }
        };
        let pubkey_bytes = keypair.to_pubkey().0;
        let mut salt = [0u8; 32];
        if let Err(e) = getrandom::fill(&mut salt) {
            update_task_error(
                &tasks_clone,
                &task_id_clone,
                format!("Failed to generate secure random salt: {}", e),
            );
            return;
        }
        let sig_bytes = match hex::decode(&raw_kyn.signature) {
            Ok(b) => b,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Failed to decode Beacon signature: {}", e),
                );
                return;
            }
        };

        let challenge = kinetic_core::types::Commitment::derive(
            kinetic_core::constants::NETWORK_SALT,
            &fqdn,
            &salt,
            &sig_bytes,
            &kinetic_primitives::keypairs::IdentityPubKey(pubkey_bytes.to_vec()),
        );

        // Step 4: VDF Evaluation (Blocking)
        update_task_status(
            &tasks_clone,
            &task_id_clone,
            "Computing Renewal VDF... (this may take a while)",
            30,
        );

        let required_iters =
            kinetic_core::consensus_math::ConsensusParams::default().iterations(&fqdn);
        // Renewals get an 80% discount
        let discounted_iters = (required_iters as f64 * 0.2) as u64;
        let actual_iterations = std::cmp::max(iterations, discounted_iters);

        let vdf_engine = kinetic_vdf::RsaVdfEngine::new();
        let challenge_clone = challenge.clone();

        let permit_res = state.vdf_semaphore.clone().acquire_owned().await;
        if permit_res.is_err() {
            update_task_error(&tasks_clone, &task_id_clone, "VDF Semaphore closed".into());
            return;
        }
        let permit = permit_res.unwrap();

        let proof = match tokio::task::spawn_blocking(move || {
            use kinetic_core::traits::VdfEngine;
            vdf_engine.evaluate(&challenge_clone, actual_iterations)
        })
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("VDF engine error: {}", e),
                );
                return;
            }
            Err(e) => {
                update_task_error(&tasks_clone, &task_id_clone, format!("Task panic: {}", e));
                return;
            }
        };

        drop(permit);

        // Broadcast commitment now that the renewal proof exists (Option B / C-1 fix).
        update_task_status(&tasks_clone, &task_id_clone, "Broadcasting Commitment", 85);
        let commit_bytes = match serde_json::to_vec(&challenge) {
            Ok(b) => b,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Commitment serialization error: {}", e),
                );
                return;
            }
        };
        if let Err(e) = network_clone
            .publish_redundant_payload(&fqdn, commit_bytes)
            .await
        {
            update_task_error(
                &tasks_clone,
                &task_id_clone,
                format!("DHT Commit Error: {}", e),
            );
            return;
        }

        // Wait enough kyns to satisfy the commit_age rule in verify_reveal.
        let wait_secs = kinetic_core::constants::CONSENSUS_MINIMUM_COMMIT_AGE_KYNS + 2;
        update_task_status(
            &tasks_clone,
            &task_id_clone,
            &format!("Maturing commitment ({} s)...", wait_secs),
            88,
        );
        tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;

        update_task_status(&tasks_clone, &task_id_clone, "Publishing Renewal", 90);

        let previous_proof = kinetic_core::types::PreviousProof {
            salt: old_reveal.salt,
            kyn: old_reveal.kyn,
            beacon_signature: old_reveal.beacon_signature.clone(),
            iterations: old_reveal.iterations,
            vdf_proof: old_reveal.vdf_proof.clone(),
            identity_signature: old_reveal.identity_signature.clone(),
        };

        let mut new_reveal = kinetic_core::types::Reveal {
            protocol_version: 1,
            name: fqdn.clone(),
            payload: old_reveal.payload.clone(), // Keep existing zone payload
            salt,
            kyn: kinetic_kyn::types::TargetKyn::from(raw_kyn.kyn()),
            beacon_signature: raw_kyn.signature.clone(),
            iterations: actual_iterations,
            vdf_proof: kinetic_core::types::VdfProof {
                proof_bytes: proof.proof_bytes,
            },
            pubkey: kinetic_primitives::keypairs::IdentityPubKey(pubkey_bytes.to_vec()),
            identity_signature: kinetic_primitives::keypairs::IdentitySignature(vec![]),
            authorization: None,
            previous_proof: Some(previous_proof),
        };

        let signable = new_reveal.signable_bytes(kinetic_core::constants::NETWORK_SALT);
        new_reveal.identity_signature = keypair.sign(&signable);

        let reveal_bytes = match serde_json::to_vec(&new_reveal) {
            Ok(b) => b,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Serialization failed in VDF task: {}", e),
                );
                return;
            }
        };
        if let Err(e) = network_clone
            .publish_redundant_payload(&fqdn, reveal_bytes.clone())
            .await
        {
            update_task_error(
                &tasks_clone,
                &task_id_clone,
                format!("DHT Publish Error: {}", e),
            );
            return;
        }

        let local_reveal_key = format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, fqdn);
        let _ = storage_clone.put(local_reveal_key.as_bytes(), &reveal_bytes);

        update_task_status(&tasks_clone, &task_id_clone, "Complete", 100);
    });

    Ok(Json(serde_json::json!({
        "task_id": task_id,
        "message": "Renewal VDF generation started"
    })))
}

pub(crate) fn update_task_status(
    tasks: &Arc<Mutex<HashMap<String, VdfTaskStatus>>>,
    id: &str,
    status: &str,
    progress: u64,
) {
    if let Ok(mut map) = tasks.lock()
        && let Some(task) = map.get_mut(id)
    {
        task.status = status.to_string();
        task.progress = progress;
    }
}

pub(crate) fn update_task_error(
    tasks: &Arc<Mutex<HashMap<String, VdfTaskStatus>>>,
    id: &str,
    err: String,
) {
    if let Ok(mut map) = tasks.lock()
        && let Some(task) = map.get_mut(id)
    {
        task.error = Some(err);
        task.status = "Failed".to_string();
    }
}

/// Retrieves all running or recently completed VDF tasks.
pub async fn handle_macro_tasks(
    Extension(role): Extension<Role>,
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_vdf() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }
    let tasks = {
        let map = state.vdf_tasks.lock().unwrap_or_else(|e| e.into_inner());
        map.clone()
    };
    Ok(Json(serde_json::to_value(tasks).unwrap_or_default()))
}

/// Retrieves the current progress and status of a VDF task by ID.
pub async fn handle_macro_status(
    Extension(role): Extension<Role>,
    Path(task_id): Path<String>,
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_vdf() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }
    let task = {
        let tasks = state.vdf_tasks.lock().unwrap_or_else(|e| e.into_inner());
        tasks.get(&task_id).cloned()
    };

    match task {
        Some(t) => Ok(Json(serde_json::to_value(t).unwrap_or_default())),
        None => Ok(Json(serde_json::json!({"error": "Task not found"}))),
    }
}
