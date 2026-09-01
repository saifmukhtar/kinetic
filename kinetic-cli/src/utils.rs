//! CLI utility functions for Bearer token loading, HTTP client configuration, and API error formatting.

use anyhow::Context;
use kinetic_local::config::get_zones_dir;
use reqwest::Client;
use std::time::Duration;

/// Parses and formats an API error from an HTTP response.
///
/// This function attempts to deserialize the response body into an `ApiError`.
/// If successful, it constructs a user-friendly error string; otherwise, it falls
/// back to a generic HTTP error string including the status and raw body.
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

/// Saves a DNS zone to a file on disk.
///
/// This creates a JSON file in the configured zones directory using the given FQDN as the filename.
///
/// # Errors
/// Returns an `anyhow::Error` if the FQDN apex name is invalid, or if the directory cannot be created or the file cannot be written.
pub fn save_zone_file(fqdn: &str, zone: &kinetic_core::types::NrsZone) -> anyhow::Result<()> {
    if let Err(e) = kinetic_core::types::names::is_valid_apex_name(fqdn) {
        anyhow::bail!("Invalid apex name: {:?}", e);
    }
    let zones_dir = get_zones_dir();
    std::fs::create_dir_all(&zones_dir).context("Failed to create zones directory")?;
    let path = zones_dir.join(format!("{}.json", fqdn));
    let json_str = serde_json::to_string_pretty(zone).context("Failed to serialize zone data")?;
    std::fs::write(path, json_str).context("Failed to write zone file to disk")
}

/// Retrieves the API authentication token from the configured token path.
///
/// # Errors
/// Returns an `anyhow::Error` if the token file cannot be read, which likely indicates
/// Reads the admin API token from the `tokens/admin.token` file.
pub fn get_api_token() -> anyhow::Result<String> {
    let path = kinetic_local::config::get_api_tokens_dir().join("admin.token");
    let token = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read admin API token from {:?}", path))?;
    Ok(token.trim().to_string())
}

/// Builds an HTTP `reqwest::Client` with the default authorization headers.
///
/// Automatically retrieves the API token and configures it in the headers.
///
/// # Errors
/// Returns an `anyhow::Error` if the token cannot be retrieved, or if the client
/// builder fails to initialize.
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
        let body = r#"{"type":"about:blank","title":"Bad Request","status":400,"detail":"Invalid name format","code":"400","retryable":false,"request_id":"req-1234","details":null}"#;

        let result =
            parse_and_format_api_error("Test Context", reqwest::StatusCode::BAD_REQUEST, body);
        assert_eq!(result, "[400] Test Context: Invalid name format");
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
