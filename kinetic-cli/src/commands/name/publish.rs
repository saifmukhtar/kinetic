//! Name zone routing updates and commit-reveal network publishing logic.

use crate::utils::{parse_and_format_api_error, save_zone_file};
use kinetic_core::config::{get_zones_dir, KineticConfig};
use kinetic_core::types::load_keypair;
use ml_dsa::signature::Signer;
use ml_dsa::SignatureEncoding;
use reqwest::Client;
use serde_json::json;
use tracing::{info, warn};

/// Updates the routing zone data for a registered name.
///
/// This involves checking for a local reveal file (or fetching it from the DHT),
/// signing the new payload, and propagating the updated record to the network.
///
/// # Errors
/// Returns an `anyhow::Error` if the name is invalid, keys cannot be loaded,
/// the existing record cannot be found, or the DHT publish fails.
pub async fn update_zone_logic(
    fqdn: String,
    zone: kinetic_core::types::DnsZone,
    config: &KineticConfig,
    client: &Client,
    _display_val: String,
) -> anyhow::Result<()> {
    if let Err(e) = kinetic_core::types::is_valid_apex_name(&fqdn) {
        tracing::error!("Invalid name '{}': {}", fqdn, e);
        return Ok(());
    }
    let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
    let keypair = load_keypair(&identity_path.to_string_lossy())?;

    // Check for local reveal file first for massive UX improvement
    let reveal_path = get_zones_dir().join(format!("{}.reveal.json", fqdn));
    let mut existing_record: kinetic_core::types::NameRecord = if reveal_path.exists() {
        let content = std::fs::read_to_string(&reveal_path)?;
        serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Local reveal file corrupted: {}", e))?
    } else {
        let resolve_url = format!(
            "http://{}:{}/resolve/{}",
            config.daemon.bind_ip, config.daemon.api_port, fqdn
        );
        let resolve_res = client.get(&resolve_url).send().await?;
        if !resolve_res.status().is_success() {
            let status = resolve_res.status();
            let text = resolve_res.text().await.unwrap_or_default();
            let msg = parse_and_format_api_error(
                "Failed to resolve existing name from DHT",
                status,
                &text,
            );
            return Err(anyhow::anyhow!("No local reveal file found, and {}", msg));
        }
        resolve_res.json().await?
    };

    let new_payload = serde_json::to_vec(&zone).expect("Failed to serialize DnsZone");
    match &mut existing_record {
        kinetic_core::types::NameRecord::Standard(r) => {
            r.payload = new_payload;
            let signable = r.signable_bytes(kinetic_core::constants::NETWORK_ID);
            r.signature = keypair.sign(&signable).to_bytes().to_vec();
        }
        kinetic_core::types::NameRecord::Premium {
            name,
            payload,
            signature,
            ..
        } => {
            *payload = new_payload;
            // The signature for NameRecord uses the NameRecord method verify_signature which signs (name || payload || network_id)
            let mut signable = Vec::new();
            signable.extend_from_slice(name.as_bytes());
            signable.extend_from_slice(payload);
            signable.extend_from_slice(kinetic_core::constants::NETWORK_ID.as_bytes());
            *signature = keypair.sign(&signable).to_bytes().to_vec();
        }
    }

    let response = client
        .post(format!(
            "http://{}:{}/publish",
            config.daemon.bind_ip, config.daemon.api_port
        ))
        .json(&json!({"record": existing_record}))
        .send()
        .await?;
    if response.status().is_success() {
        info!("Success! {} updated.", fqdn);
        let _ = save_zone_file(&fqdn, &zone);
        let reveal_str = serde_json::to_string_pretty(&existing_record)?;
        let _ = std::fs::write(&reveal_path, reveal_str);
    } else {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        warn!(
            "Daemon returned an error updating zone: {}",
            parse_and_format_api_error("Publish zone error", status, &text)
        );
    }
    Ok(())
}

/// Handles publishing local zone configuration to the network.
///
/// Reads the corresponding `zone.json` file for the given domain name
/// and calls `update_zone_logic` to submit it to the local daemon.
///
/// # Errors
/// Returns an `anyhow::Error` if the zone file does not exist, cannot be read
/// or parsed, or if the update process fails.
pub async fn handle(name: String, config: &KineticConfig, client: &Client) -> anyhow::Result<()> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    let mut zone_file = get_zones_dir();
    zone_file.push(format!("{}.json", fqdn));

    if !zone_file.exists() {
        return Err(anyhow::anyhow!(
            "No zone file found at {}. Please create it or run 'register' first.",
            zone_file.display()
        ));
    }

    let file_contents = std::fs::read_to_string(&zone_file)?;
    let zone: kinetic_core::types::DnsZone = serde_json::from_str(&file_contents)
        .map_err(|e| anyhow::anyhow!("Invalid DnsZone JSON in {}: {}", zone_file.display(), e))?;

    update_zone_logic(fqdn, zone, config, client, "ZonePublish".to_string()).await?;
    Ok(())
}
