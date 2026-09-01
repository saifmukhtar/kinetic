//! New .kin name registration engine featuring Drand entropy, two-phase commitment, and VDF proof generation.

use crate::utils::{parse_and_format_api_error, save_zone_file};
use kinetic_core::config::KineticConfig;
use kinetic_core::traits::{KynProvider, VdfEngine};
use kinetic_core::types::Reveal;
use kinetic_local::config::get_zones_dir;
use kinetic_local::identity::load_keypair;

use reqwest::Client;
use serde_json::json;

use std::time::Duration;
use tracing::{info, warn};

/// Handles the registration of a new `.kin` name.
///
/// This involves fetching the latest Drand beacon for entropy, generating a VDF
/// proof (which can be computationally intensive), creating/inheriting a Kinetic
/// Identity Document (KID) for the name, and submitting the resulting proof
/// and zone configuration to the local daemon for DHT propagation.
///
/// # Errors
/// Returns an `anyhow::Error` if Drand fetching, proof generation, identity loading,
/// or network broadcast fails.
pub async fn handle_name_register(
    name: String,
    iterations: u64,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    let fqdn = kinetic_core::types::normalize_name(&name);

    info!(
        "Starting registration process for '{}' ({} iterations)",
        fqdn, iterations
    );

    // 1. Fetch latest Drand beacon
    info!("Fetching latest Drand entropy beacon...");
    let kyn_provider = kinetic_network::client::drand::DrandProvider::new(None);
    let drand_data = kyn_provider.fetch_latest().await?;
    info!(
        "Successfully fetched Drand kyn {}. Randomness: {}",
        drand_data.kyn, drand_data.randomness
    );

    // 2. Generate the VDF Proof
    info!("Initializing Chia VDF Engine. Generating cryptographic proof...");
    let vdf_engine = kinetic_vdf_rsa::RsaVdfEngine::new();

    // Generate a random salt to prevent pre-computation attacks
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).expect("Failed to generate random salt");

    // Construct commitment: H(name || salt || drand_signature || pubkey)
    let identity_path = kinetic_local::config::get_base_dir().join("identity.key");
    let keypair = load_keypair(&identity_path)?;
    let pubkey = keypair.pubkey_bytes();

    let drand_sig_bytes = hex::decode(&drand_data.signature)
        .map_err(|_| anyhow::anyhow!("Received corrupted Drand signature from the beacon"))?;
    let challenge = kinetic_core::types::Commitment::derive(
        kinetic_core::constants::NETWORK_SALT,
        &fqdn,
        &salt,
        &drand_sig_bytes,
        &pubkey,
    );

    // Phase 4.1: POST the commitment *before* generating the VDF proof
    info!("Broadcasting Commitment to DHT (Phase 1 of 2)...");
    let commit_req = kinetic_core::types::CommitRequest {
        name: fqdn.clone(),
        commitment: challenge.clone(),
    };
    let commit_res = client
        .post(format!(
            "http://{}:{}/commit",
            config.daemon.bind_ip, config.daemon.api_port
        ))
        .json(&commit_req)
        .send()
        .await?;
    if !commit_res.status().is_success() {
        let status = commit_res.status();
        let err_text = commit_res.text().await.unwrap_or_default();
        let msg = parse_and_format_api_error("Failed to broadcast commitment", status, &err_text);
        return Err(anyhow::anyhow!("{}", msg));
    }
    info!("Commitment accepted. Starting VDF computation (Phase 2 of 2)...");

    let required_iterations =
        kinetic_core::consensus_math::ConsensusParams::default().iterations(&fqdn);
    let actual_iterations = std::cmp::max(iterations, required_iterations);

    let label = kinetic_core::types::names::extract_apex_name(&fqdn);
    let label = label
        .strip_suffix(kinetic_core::constants::NSP_SUFFIX)
        .unwrap_or(&label);

    let expected_minutes = (actual_iterations as f64
        / kinetic_core::constants::BASE_ITERATIONS as f64)
        * kinetic_core::constants::TARGET_MINUTES;
    let time_str = if expected_minutes >= 1440.0 {
        format!("{:.1} days", expected_minutes / 1440.0)
    } else if expected_minutes >= 60.0 {
        format!("{:.1} hours", expected_minutes / 60.0)
    } else {
        format!("{:.0} minutes", expected_minutes)
    };

    if !label.is_empty() && label.len() <= 6 {
        warn!("================================================================");
        warn!(
            "CRITICAL WARNING: You are attempting to register a {}-letter name.",
            label.len()
        );
        warn!("Short names require massive VDF computations to prevent squatting.");
        warn!(
            "This requires {} iterations and will take approximately {} of continuous CPU time.",
            actual_iterations, time_str
        );
        warn!(
            "(Note: This expected time assumes an Intel Core i5-11400H equivalent CPU or better)."
        );
        warn!(
            "If your computer sleeps, restarts, or loses power during this process, ALL PROGRESS WILL BE LOST."
        );
        warn!("================================================================");
        info!("Starting in 15 seconds. Press Ctrl+C NOW to cancel...");
        tokio::time::sleep(Duration::from_secs(15)).await;
    } else {
        info!(
            "This name requires {} iterations and will take approximately {}.",
            actual_iterations, time_str
        );
    }

    let refresh_challenge = challenge.clone();
    let refresh_fqdn = fqdn.clone();
    let refresh_port = config.daemon.api_port;
    let refresh_client = client.clone();
    let refresh_bind_ip = config.daemon.bind_ip.clone();

    // Phase 4.1.5: Spawn a backgkyn task to refresh the commitment periodically
    let refresh_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour
        loop {
            interval.tick().await; // The first tick completes immediately
            let commit_req = kinetic_core::types::CommitRequest {
                name: refresh_fqdn.clone(),
                commitment: refresh_challenge.clone(),
            };
            let _ = refresh_client
                .post(format!(
                    "http://{}:{}/commit",
                    refresh_bind_ip, refresh_port
                ))
                .json(&commit_req)
                .send()
                .await;
        }
    });

    // Run VDF evaluation in a blocking thread so we don't starve the async runtime
    let challenge_clone = challenge.clone();
    let actual_iterations_clone = actual_iterations;
    let proof = tokio::task::spawn_blocking(move || {
        vdf_engine.evaluate(&challenge_clone, actual_iterations_clone)
    })
    .await??;

    refresh_handle.abort();
    info!("VDF Proof successfully generated!");
    info!("Proof: {}", hex::encode(&proof.proof_bytes));

    // 3. Construct the NrsZone and auto-generate/inherit KID
    let mut records = std::collections::HashMap::new();

    let kyn_provider = kinetic_network::client::drand::DrandProvider::new(None);
    use kinetic_core::types::Kyn;
    use kinetic_core::types::clock::KynNetworkExt;

    let current_kyn = match kyn_provider.fetch_latest().await {
        Ok(kyn) => Kyn(kyn.kyn),
        Err(_) => Kyn::now_local(),
    };

    let kid_res = kinetic_local::kid_manager::get_or_create_kid_for_name(
        &fqdn,
        true,
        false,
        current_kyn,
        &identity_path,
    )?;
    if kid_res.is_inherited {
        info!("Inheriting apex KID for {}: {}", fqdn, kid_res.did);
    } else {
        info!("Generated new KID for {}: {}", fqdn, kid_res.did);
    }

    // Map the apex of the zone to this KID
    records.insert(
        "@".to_string(),
        vec![kinetic_core::types::NrsRecord::KID(kid_res.did)],
    );

    let zone = kinetic_core::types::NrsZone { records };
    let payload = serde_json::to_vec(&zone).expect("Failed to serialize NrsZone");

    let mut reveal = Reveal {
        protocol_version: 1,
        name: fqdn.clone(),
        payload,
        salt,
        kyn: drand_data.kyn,
        drand_signature: drand_data.signature.clone(),
        iterations: actual_iterations,
        vdf_proof: kinetic_core::types::VdfProof {
            proof_bytes: proof.proof_bytes,
        },
        pubkey: pubkey.to_vec(),
        signature: vec![],
        authorization: None,
        previous_proof: None,
        miner_pubkey: None,
    };

    let signable = reveal.signable_bytes(kinetic_core::constants::NETWORK_SALT);
    reveal.signature = keypair.sign(&signable);

    // 4. Submit to local Daemon via REST API
    info!("Submitting fully signed Reveal tuple to local Kinetic Daemon...");
    let daemon_url = format!(
        "http://{}:{}/publish",
        config.daemon.bind_ip, config.daemon.api_port
    );

    let req_body = json!({
        "reveal": reveal,
    });

    let response = client.post(daemon_url).json(&req_body).send().await;

    match response {
        Ok(res) if res.status().is_success() => {
            info!(
                "Success! {} has been published to the Kinetic DHT network.",
                fqdn
            );
            let _ = save_zone_file(&fqdn, &zone);
            let reveal_path = get_zones_dir().join(format!("{}.reveal.json", fqdn));
            let record = kinetic_core::types::NameRecord::Standard(Box::new(reveal));
            let reveal_str =
                serde_json::to_string_pretty(&record).expect("Failed to serialize Reveal");
            let _ = std::fs::write(&reveal_path, reveal_str);
            info!(
                "Your zone configuration was saved to {}/{}.json",
                get_zones_dir().display(),
                fqdn
            );
            info!("Your reveal proof was saved to {}", reveal_path.display());
        }
        Ok(res) => {
            warn!("Daemon returned an error: {}", res.status());
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            warn!(
                "{}",
                parse_and_format_api_error("Publish error", status, &text)
            );
        }
        Err(e) => {
            warn!("Failed to connect to local daemon: {}", e);
            warn!("Are you sure `kinetic-daemon` is running?");
        }
    }
    Ok(())
}
