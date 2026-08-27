//! Name renewal engine with cryptographic proof chaining and owner VDF difficulty discounts.

use crate::utils::parse_and_format_api_error;
use kinetic_core::config::{KineticConfig, get_zones_dir};
use kinetic_core::traits::VdfEngine;
use kinetic_core::types::load_keypair;

use reqwest::Client;

use std::time::Duration;
use tracing::info;

/// Handles name renewal.
///
/// Renews an existing `.kin` name by fetching the latest Drand beacon,
/// computing a discounted VDF proof based on the previous proof, and publishing
/// the new `Reveal` to the DHT. This extends the lifespan of the registration.
///
/// # Errors
/// Returns an `anyhow::Error` if the previous reveal is not found locally,
/// keypairs don't match, or network/VDF generation steps fail.
pub async fn handle(
    name: String,
    iterations: u64,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    info!("Starting renewal for '{}'", fqdn);

    let reveal_path = get_zones_dir().join(format!("{}.reveal.json", fqdn));
    let old_reveal: kinetic_core::types::Reveal = if reveal_path.exists() {
        let content = std::fs::read_to_string(&reveal_path)?;
        let record: kinetic_core::types::NameRecord = serde_json::from_str(&content)?;
        match record {
            kinetic_core::types::NameRecord::Standard(r) => *r,
            kinetic_core::types::NameRecord::Prime { .. }
            | kinetic_core::types::NameRecord::Infra { .. } => {
                return Err(anyhow::anyhow!(
                    "Name '{}' is Prime/Infra. These names do not expire or require VDF renewal.",
                    fqdn
                ));
            }
        }
    } else {
        return Err(anyhow::anyhow!(
            "No local reveal found for '{}'. Cannot renew.",
            fqdn
        ));
    };

    let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
    let keypair = load_keypair(&identity_path)?;
    let pubkey = keypair.public_key_bytes();

    if old_reveal.pubkey != pubkey.as_slice() {
        return Err(anyhow::anyhow!(
            "Local keypair does not match the public key in the old reveal."
        ));
    }

    info!("Fetching latest Drand entropy beacon...");
    let drand_client = kinetic_core::drand::DrandClient::new(None);
    let drand_data = drand_client.fetch_latest().await?;
    info!("Successfully fetched Drand kyn {}.", drand_data.kyn);

    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).expect("Failed to generate random salt");

    let drand_sig_bytes = hex::decode(&drand_data.signature)
        .map_err(|_| anyhow::anyhow!("Received corrupted Drand signature from the beacon"))?;
    let challenge = kinetic_core::types::Commitment::derive(
        kinetic_core::constants::NETWORK_SALT,
        &fqdn,
        &salt,
        &drand_sig_bytes,
        &pubkey,
    );

    info!("Broadcasting Commitment to DHT...");
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
    info!("Commitment accepted. Starting discounted VDF computation...");

    let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
    let base_iterations = consensus_math.required_iterations(&fqdn);

    // 80% discount
    let discounted_iterations = std::cmp::max(1, base_iterations / 5);
    let actual_iterations = std::cmp::max(iterations, discounted_iterations);
    info!(
        "Using discounted iteration count: {} (base was {})",
        actual_iterations, base_iterations
    );

    let refresh_challenge = challenge.clone();
    let refresh_fqdn = fqdn.clone();
    let refresh_port = config.daemon.api_port;
    let refresh_client = client.clone();
    let refresh_bind_ip = config.daemon.bind_ip.clone();
    let refresh_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour
        loop {
            interval.tick().await;
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

    let vdf_engine = kinetic_vdf_rsa::RsaVdfEngine::new();
    let vdf_proof =
        tokio::task::spawn_blocking(move || vdf_engine.evaluate(&challenge, actual_iterations))
            .await??;

    refresh_handle.abort();

    let mut previous_proof = kinetic_core::types::PreviousProof {
        salt: old_reveal.salt,
        kyn: old_reveal.kyn,
        drand_signature: old_reveal.drand_signature.clone(),
        iterations: old_reveal.iterations,
        vdf_proof: old_reveal.vdf_proof.clone(),
        signature: vec![],
    };

    let prev_signable = previous_proof.signable_bytes(kinetic_core::constants::NETWORK_SALT);
    previous_proof.signature = keypair.sign(&prev_signable);

    let mut new_reveal = kinetic_core::types::Reveal {
        protocol_version: 1,
        name: fqdn.clone(),
        payload: old_reveal.payload.clone(),
        salt,
        kyn: drand_data.kyn,
        drand_signature: drand_data.signature.clone(),
        iterations: actual_iterations,
        vdf_proof,
        pubkey: pubkey.to_vec(),
        signature: vec![],
        authorization: None,
        previous_proof: Some(previous_proof),
        miner_pubkey: None,
    };

    new_reveal.signature = keypair
        .sign(&new_reveal.signable_bytes(kinetic_core::constants::NETWORK_SALT));

    let req_body = serde_json::json!({
        "reveal": new_reveal,
    });
    let res = client
        .post(format!(
            "http://{}:{}/publish",
            config.daemon.bind_ip, config.daemon.api_port
        ))
        .json(&req_body)
        .send()
        .await?;

    if res.status().is_success() {
        info!("Successfully renewed '{}'!", fqdn);
        let record = kinetic_core::types::NameRecord::Standard(Box::new(new_reveal));
        std::fs::write(&reveal_path, serde_json::to_string_pretty(&record)?)?;
    } else {
        let status = res.status();
        let err_text = res.text().await.unwrap_or_default();
        let msg = parse_and_format_api_error("Failed to publish renewal", status, &err_text);
        return Err(anyhow::anyhow!("{}", msg));
    }
    Ok(())
}
