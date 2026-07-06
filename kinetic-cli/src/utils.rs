use kinetic_core::config::get_zones_dir;
use reqwest::Client;
use std::time::Duration;

pub fn parse_and_format_api_error(
    context: &str,
    status: reqwest::StatusCode,
    body: &str,
) -> String {
    if let Ok(api_err) = serde_json::from_str::<kinetic_core::ApiError>(body) {
        format!("[{}] {}: {}", api_err.code, context, api_err.detail)
    } else {
        format!("{}: HTTP {} - {}", context, status, body)
    }
}

pub fn save_zone_file(
    fqdn: &str,
    zone: &kinetic_core::types::DnsZone,
) -> Result<(), std::io::Error> {
    let zones_dir = get_zones_dir();
    std::fs::create_dir_all(&zones_dir)?;
    let path = zones_dir.join(format!("{}.json", fqdn));
    let json_str = serde_json::to_string_pretty(zone)?;
    std::fs::write(path, json_str)
}

pub fn get_api_token() -> anyhow::Result<String> {
    let path = kinetic_core::config::get_api_token_path();
    std::fs::read_to_string(&path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read API token from {}: {}. Is kinetic-daemon running?",
            path.display(),
            e
        )
    })
}

pub fn build_client(timeout_secs: u64) -> anyhow::Result<Client> {
    let token = get_api_token()?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))?,
    );

    Ok(Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .default_headers(headers)
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_format_api_error_valid_json() {
        let body = r#"{"type":"about:blank","title":"Bad Request","status":400,"detail":"Invalid domain format","code":"400","retryable":false,"request_id":"req-1234","details":null}"#;

        let result =
            parse_and_format_api_error("Test Context", reqwest::StatusCode::BAD_REQUEST, body);
        assert_eq!(result, "[400] Test Context: Invalid domain format");
    }

    #[test]
    fn test_parse_and_format_api_error_invalid_json() {
        let body = "Not Found Error Page HTML";
        let result =
            parse_and_format_api_error("Test Context", reqwest::StatusCode::NOT_FOUND, body);
        assert_eq!(
            result,
            "Test Context: HTTP 404 Not Found - Not Found Error Page HTML"
        );
    }
}
