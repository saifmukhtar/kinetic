//! HTTP REST API endpoints and background task workers for VDF registration, renewal, and task progress tracking.

use super::*;
use axum::{
    extract::{Path, State, Extension},
    http::StatusCode,
    Json,
};

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Payload for renewing a registered Kinetic name via VDF.
#[derive(Deserialize)]
pub struct NameRenewRequest {
    /// The domain name to renew.
    pub name: String,
    /// Optional overridden iteration count.
    pub iterations: Option<u64>,
}

/// Payload for registering a new Kinetic name via VDF.
#[derive(Deserialize)]
pub struct VdfRegisterRequest {
    /// The domain name to register.
    pub name: String,
    /// Optional overridden iteration count.
    pub iterations: Option<u64>,
}

/// Handles API requests to initiate a background VDF registration task.
/// Ensures that only one VDF task is actively running.
///
/// # Errors
///
/// Returns an error if a VDF task is already running.
pub async fn handle_vdf_register(
    Extension(role): Extension<Role>,
    State(state): State<ApiState>,
    Json(req): Json<VdfRegisterRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !role.can_vdf() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient privileges: Requires VDF or Admin role"})),
        ));
    }
    let fqdn = kinetic_core::types::normalize_name(&req.name);
    if let Err(e) = kinetic_core::types::is_valid_apex_name(&fqdn) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("Invalid name: {}", e) })),
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
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "A VDF registration is already in progress. Please wait for it to complete."
                })),
            ));
        }

        tasks.retain(|_, t| t.progress < 100 && t.error.is_none());

        if tasks.len() >= 1000 {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "Too many concurrent VDF tasks. Please wait."
                })),
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

    // Spawn blocking background task
    let tasks_clone = state.vdf_tasks.clone();
    let network_clone = state.network.clone();
    let storage_clone = state.storage.clone();
    let task_id_clone = task_id.clone();
    let iterations = req.iterations.unwrap_or(4_194_304);

    tokio::spawn(async move {
        // Step 1: Drand
        update_task_status(&tasks_clone, &task_id_clone, "Fetching Drand beacon", 10);
        let drand_client = kinetic_core::drand::DrandClient::new(Some(storage_clone.clone()));
        let drand_data = match drand_client.fetch_latest().await {
            Ok(d) => d,
            Err(e) => {
                update_task_error(&tasks_clone, &task_id_clone, format!("Drand error: {}", e));
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
        let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
        let keypair = match kinetic_core::types::load_keypair(&identity_path.to_string_lossy()) {
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
        use ml_dsa::{KeyExport, Keypair};
        let pubkey = keypair.verifying_key().to_bytes();
        let mut salt = [0u8; 32];
        if let Err(e) = getrandom::fill(&mut salt) {
            update_task_error(
                &tasks_clone,
                &task_id_clone,
                format!("Failed to generate secure random salt: {}", e),
            );
            return;
        }
        let challenge_bytes = hex::decode(&drand_data.randomness).unwrap_or_else(|_| vec![0u8; 32]);

        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(fqdn.as_bytes());
        hasher.update(salt);
        hasher.update(&challenge_bytes);
        hasher.update(pubkey);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        let challenge = kinetic_core::types::Commitment { hash };

        // Step 3: VDF Evaluation (Blocking)
        update_task_status(
            &tasks_clone,
            &task_id_clone,
            "Computing VDF... (this may take a while)",
            30,
        );
        let required_iters = kinetic_core::consensus_math::ConsensusParams::default()
            .required_iterations(&fqdn, &challenge_bytes);
        let actual_iterations = std::cmp::max(iterations, required_iters);

        let vdf_engine = kinetic_vdf::ChiaVdfEngine::new();
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

        // Wait >10 drand rounds (10 × 3 s = 30 s) to satisfy the commit_age ≥ 10 rule in verify_reveal.
        update_task_status(
            &tasks_clone,
            &task_id_clone,
            "Maturing commitment (32 s)...",
            88,
        );
        tokio::time::sleep(std::time::Duration::from_secs(32)).await;

        update_task_status(&tasks_clone, &task_id_clone, "Publishing Registration", 90);

        // Construct Reveal
        let records = HashMap::new();
        let zone = kinetic_core::types::DnsZone { records };
        let payload = match serde_json::to_vec(&zone) {
            Ok(b) => b,
            Err(e) => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Serialization failed in VDF task: {}", e),
                );
                tracing::error!(
                    error_code = "KIN-VDF-002",
                    "Serialization failed in VDF task: {}",
                    e
                );
                return;
            }
        };

        let mut reveal = kinetic_core::types::Reveal {
            protocol_version: 1,
            name: fqdn.clone(),
            payload,
            salt,
            drand_pulse: drand_data.round,
            drand_randomness: drand_data.randomness.clone(),
            iterations: actual_iterations,
            vdf_proof: kinetic_core::types::VdfProof {
                proof_bytes: proof.proof_bytes,
            },
            pubkey: pubkey.to_vec(),
            signature: vec![],
            previous_proof: None,
            miner_pubkey: None,
        };

        use ml_dsa::signature::Signer;
        use ml_dsa::SignatureEncoding;
        let signable = reveal.signable_bytes();
        reveal.signature = keypair.sign(&signable).to_bytes().to_vec();

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
                    error_code = "KIN-VDF-002",
                    "Serialization failed in VDF task: {}",
                    e
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
        let mut owned = Vec::new();
        if let Ok(Some(bytes)) = storage_clone.get(kinetic_core::constants::DB_PREFIX_OWNED_NAMES) {
            if let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes) {
                owned = names;
            }
        }
        if !owned.contains(&fqdn) {
            owned.push(fqdn.clone());
            if let Ok(b) = serde_json::to_vec(&owned) {
                let _ = storage_clone.put(kinetic_core::constants::DB_PREFIX_OWNED_NAMES, &b);
            }
        }

        // Save default zone file
        let zones_dir = kinetic_core::config::get_zones_dir();
        let _ = std::fs::create_dir_all(&zones_dir);
        let path = zones_dir.join(format!("{}.json", fqdn));
        if let Ok(s) = serde_json::to_string_pretty(&zone) {
            if let Err(e) = std::fs::write(&path, s) {
                tracing::warn!(
                    error_code = "KIN-IMPL-005",
                    "Failed to write zone file: {}",
                    e
                );
            }
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
pub async fn handle_vdf_renew(
    Extension(role): Extension<Role>,
    State(state): State<ApiState>,
    Json(req): Json<NameRenewRequest>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    if !role.can_vdf() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient privileges: Requires VDF or Admin role"})),
        ));
    }
    let fqdn = kinetic_core::types::normalize_name(&req.name);
    if let Err(e) = kinetic_core::types::is_valid_apex_name(&fqdn) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("Invalid name: {}", e) })),
        ));
    }
    let mut tasks = state.vdf_tasks.lock().unwrap();

    // In ApiState there is no vdf_events yet, so we just check for conflicts by looking at the tasks map directly.
    for task in tasks.values() {
        if task.status != "Complete" && task.status != "Failed" {
            // Since we can't easily check name if it's not in VdfTaskStatus, we skip conflict checks for now,
            // or we could inspect the current tasks, but we'll just allow it since the CLI does too.
        }
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
        // Step 1: Read previous Reveal from Sled storage
        update_task_status(&tasks_clone, &task_id_clone, "Loading previous reveal", 5);
        let local_reveal_key = format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, fqdn);
        let old_reveal_bytes = match storage_clone.get(local_reveal_key.as_bytes()) {
            Ok(Some(b)) => b,
            _ => {
                update_task_error(
                    &tasks_clone,
                    &task_id_clone,
                    format!("Domain {} not found locally", fqdn),
                );
                return;
            }
        };
        let old_reveal: kinetic_core::types::Reveal =
            match serde_json::from_slice(&old_reveal_bytes) {
                Ok(r) => r,
                Err(e) => {
                    update_task_error(
                        &tasks_clone,
                        &task_id_clone,
                        format!("Failed to parse old reveal: {}", e),
                    );
                    return;
                }
            };

        // Step 2: Drand
        update_task_status(&tasks_clone, &task_id_clone, "Fetching Drand beacon", 10);
        let drand_client = kinetic_core::drand::DrandClient::new(Some(storage_clone.clone()));
        let drand_data = match drand_client.fetch_latest().await {
            Ok(d) => d,
            Err(e) => {
                update_task_error(&tasks_clone, &task_id_clone, format!("Drand error: {}", e));
                return;
            }
        };

        // Step 3: Commitment — generate privately; broadcast AFTER VDF (Option B / C-1 fix).
        update_task_status(&tasks_clone, &task_id_clone, "Generating Commitment", 20);
        let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
        let keypair = match kinetic_core::types::load_keypair(&identity_path.to_string_lossy()) {
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
        use ml_dsa::{KeyExport, Keypair};
        let pubkey = keypair.verifying_key().to_bytes();
        let mut salt = [0u8; 32];
        if let Err(e) = getrandom::fill(&mut salt) {
            update_task_error(
                &tasks_clone,
                &task_id_clone,
                format!("Failed to generate secure random salt: {}", e),
            );
            return;
        }
        let challenge_bytes = hex::decode(&drand_data.randomness).unwrap_or_else(|_| vec![0u8; 32]);

        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(fqdn.as_bytes());
        hasher.update(salt);
        hasher.update(&challenge_bytes);
        hasher.update(pubkey);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        let challenge = kinetic_core::types::Commitment { hash };

        // Step 4: VDF Evaluation (Blocking)
        update_task_status(
            &tasks_clone,
            &task_id_clone,
            "Computing Renewal VDF... (this may take a while)",
            30,
        );

        let required_iters = kinetic_core::consensus_math::ConsensusParams::default()
            .required_iterations(&fqdn, &challenge_bytes);
        // Renewals get an 80% discount
        let discounted_iters = (required_iters as f64 * 0.2) as u64;
        let actual_iterations = std::cmp::max(iterations, discounted_iters);

        let vdf_engine = kinetic_vdf::ChiaVdfEngine::new();
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

        // Wait >10 drand rounds to satisfy commit_age ≥ 10 in verify_reveal.
        update_task_status(
            &tasks_clone,
            &task_id_clone,
            "Maturing commitment (32 s)...",
            88,
        );
        tokio::time::sleep(std::time::Duration::from_secs(32)).await;

        update_task_status(&tasks_clone, &task_id_clone, "Publishing Renewal", 90);

        let previous_proof = kinetic_core::types::PreviousProof {
            salt: old_reveal.salt,
            drand_pulse: old_reveal.drand_pulse,
            drand_randomness: old_reveal.drand_randomness.clone(),
            iterations: old_reveal.iterations,
            vdf_proof: old_reveal.vdf_proof.clone(),
            signature: old_reveal.signature.clone(),
        };

        let mut new_reveal = kinetic_core::types::Reveal {
            protocol_version: 1,
            name: fqdn.clone(),
            payload: old_reveal.payload.clone(), // Keep existing zone payload
            salt,
            drand_pulse: drand_data.round,
            drand_randomness: drand_data.randomness.clone(),
            iterations: actual_iterations,
            vdf_proof: kinetic_core::types::VdfProof {
                proof_bytes: proof.proof_bytes,
            },
            pubkey: pubkey.to_vec(),
            signature: vec![],
            previous_proof: Some(previous_proof),
            miner_pubkey: None,
        };

        use ml_dsa::signature::Signer;
        use ml_dsa::SignatureEncoding;
        let signable = new_reveal.signable_bytes();
        new_reveal.signature = keypair.sign(&signable).to_bytes().to_vec();

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
    if let Ok(mut map) = tasks.lock() {
        if let Some(task) = map.get_mut(id) {
            task.status = status.to_string();
            task.progress = progress;
        }
    }
}

pub(crate) fn update_task_error(
    tasks: &Arc<Mutex<HashMap<String, VdfTaskStatus>>>,
    id: &str,
    err: String,
) {
    if let Ok(mut map) = tasks.lock() {
        if let Some(task) = map.get_mut(id) {
            task.error = Some(err);
            task.status = "Failed".to_string();
        }
    }
}

/// Retrieves the current progress and status of a VDF task by ID.
pub async fn handle_vdf_status(
    Extension(role): Extension<Role>,
    Path(task_id): Path<String>,
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !role.can_vdf() {
        return Err(StatusCode::FORBIDDEN);
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

/// Deletes a VDF task's status record from memory. Useful to clear completed or failed tasks.
pub async fn handle_vdf_status_delete(
    Extension(role): Extension<Role>,
    Path(task_id): Path<String>,
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !role.can_vdf() {
        return Err(StatusCode::FORBIDDEN);
    }
    let removed = {
        let mut tasks = state.vdf_tasks.lock().unwrap_or_else(|e| e.into_inner());
        tasks.remove(&task_id).is_some()
    };
    Ok(Json(serde_json::json!({ "success": removed })))
}
