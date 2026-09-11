use kinetic_core::config::KineticConfig;

pub async fn handle_verify(name: String, config: &KineticConfig, client: &reqwest::Client) -> anyhow::Result<()> {
    let port = config.daemon.api_port;
    let url = format!("http://{}:{}/api/v1/micro/nrs/verify/{}", config.daemon.bind_ip, port, name);
    
    // Grab admin token
    let token_path = kinetic_local::config::get_api_tokens_dir().join("admin.token");
    let token = std::fs::read_to_string(&token_path).unwrap_or_default();
    let auth_header = format!("Bearer {}", token.trim());

    let resp = client.get(&url).header("Authorization", &auth_header).send().await?;
    
    if !resp.status().is_success() {
        anyhow::bail!("Failed to verify quorum for '{}': {}", name, resp.text().await?);
    }
    
    let json: serde_json::Value = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&json)?);
    
    Ok(())
}
