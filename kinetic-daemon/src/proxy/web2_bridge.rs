use crate::proxy::ProxyError;
use hyper::body::Incoming;
use hyper::{Request, Response};
// Removed is_ssrf_safe import because we use it fully qualified now
use reqwest::Client;
use std::time::Duration;
use tokio::net::lookup_host;
use tracing::{info, warn};

/// Forwards an HTTP request to an external Web2 domain (e.g. GitHub Pages, Vercel)
/// while maintaining strict SSRF protection and preventing DNS rebinding.
pub async fn forward_to_web2_backend(
    req: Request<Incoming>,
    target_domain: &str,
) -> Result<Response<axum::body::Body>, ProxyError> {
    info!("Web2 Bridge: Routing request to {}", target_domain);

    // Extract original .kin host to rewrite redirects later
    let original_host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or(target_domain)
        .to_string();

    // 1. Manually resolve the target domain to an IP using the OS resolver.
    // Strip any existing port if present before appending :443 to prevent parsing crash
    let target_domain_clean = clean_target_domain(target_domain);
    let lookup_string = format!("{}:443", target_domain_clean);
    
    let mut addrs = match lookup_host(&lookup_string).await {
        Ok(a) => a,
        Err(e) => {
            warn!("KIN-NRS-029: Web2 Bridge: Failed to resolve {}: {}", target_domain_clean, e);
            return Err(ProxyError::NameNotFound(target_domain_clean.to_string()));
        }
    };

    // Grab the first available IP
    let socket_addr = match addrs.next() {
        Some(addr) => addr,
        None => {
            warn!("KIN-NRS-030: Web2 Bridge: No IPs found for {}", target_domain_clean);
            return Err(ProxyError::NameNotFound(target_domain_clean.to_string()));
        }
    };

    let ip_addr = socket_addr.ip();

    // 2. Strict SSRF Protection Check
    let ssrf_result = kinetic_core::net::validate_ssrf_safe(ip_addr);
    if ssrf_result.is_err() || ip_addr.is_unspecified() {
        let reason = if ip_addr.is_unspecified() {
            "Unspecified IP".to_string()
        } else {
            ssrf_result.unwrap_err().to_string()
        };
        warn!(
            "KIN-SEC-014: Web2 Bridge SSRF Blocked: {} resolved to a dangerous IP ({}). Reason: {}",
            target_domain_clean, ip_addr, reason
        );
        return Err(ProxyError::SecurityViolation(format!(
            "Web2 Bridge target resolved to a dangerous IP. Reason: {}",
            reason
        )));
    }

    // 3. Build the reqwest client securely.
    // By using `.resolve()`, we force reqwest to use the EXACT IP we just checked.
    // This makes DNS Rebinding SSRF attacks impossible.
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .no_proxy()
        // Force the resolved and verified IP for the target domain
        .resolve(target_domain_clean, socket_addr)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    // Extract the original path and query
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");

    let backend_url = format!("https://{}{}", target_domain_clean, path);

    let mut backend_req = client.request(req.method().clone(), &backend_url);

    // 4. Forward headers, but heavily override the Host header to trick the Web2 host
    for (name, value) in req.headers() {
        if name != hyper::header::HOST {
            backend_req = backend_req.header(name, value);
        }
    }
    // Set the Host header to the Web2 domain so GitHub/Vercel recognize it
    backend_req = backend_req.header("Host", target_domain_clean);

    // Execute the request (Letting the Reqwest error cleanly bubble up)
    let backend_resp = backend_req.send().await?;

    // 5. Build the response back to the user
    let mut resp_builder = Response::builder().status(backend_resp.status());

    for (name, value) in backend_resp.headers() {
        let header_name = name.as_str().to_lowercase();
        
        // Strip HSTS to prevent the browser from caching TLS directives for the .kin name
        if header_name == "strict-transport-security" {
            continue;
        }

        // Prevent the UX Redirect Leak: Rewrite Location headers back to the .kin name
        if header_name == "location" {
            if let Ok(loc_str) = value.to_str() {
                if let Some(new_loc) = rewrite_location_header(loc_str, target_domain_clean, &original_host) {
                    if let Ok(new_val) = hyper::header::HeaderValue::from_str(&new_loc) {
                        resp_builder = resp_builder.header(name, new_val);
                        continue;
                    }
                }
            }
        }
        
        resp_builder = resp_builder.header(name, value);
    }

    let body_stream = backend_resp.bytes_stream();
    let body = axum::body::Body::from_stream(body_stream);

    Ok(resp_builder.body(body)?)
}

// --- Helper Functions ---

/// Strips the port from a target domain to ensure safe DNS resolution.
pub(crate) fn clean_target_domain(target: &str) -> &str {
    target.split(':').next().unwrap_or(target)
}

/// Rewrites a Web2 Location redirect header back to the Web3 .kin name.
pub(crate) fn rewrite_location_header(
    loc_str: &str,
    target_domain_clean: &str,
    original_host: &str,
) -> Option<String> {
    if loc_str.contains(target_domain_clean) {
        Some(loc_str.replace(target_domain_clean, original_host))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_target_domain() {
        assert_eq!(clean_target_domain("saif.github.io"), "saif.github.io");
        assert_eq!(clean_target_domain("saif.github.io:8080"), "saif.github.io");
        assert_eq!(clean_target_domain("localhost:443"), "localhost");
        assert_eq!(clean_target_domain("my-vps.com:"), "my-vps.com");
    }

    #[test]
    fn test_rewrite_location_header() {
        // Standard Web2 to Web3 rewrite
        assert_eq!(
            rewrite_location_header("https://saif.github.io/about", "saif.github.io", "saif.kin").unwrap(),
            "https://saif.kin/about"
        );
        
        // Subpath and Query params
        assert_eq!(
            rewrite_location_header("https://saif.github.io/path?q=1", "saif.github.io", "saif.kin").unwrap(),
            "https://saif.kin/path?q=1"
        );

        // Ignore unrelated redirects (e.g., redirecting to twitter)
        assert_eq!(
            rewrite_location_header("https://twitter.com/saif", "saif.github.io", "saif.kin"),
            None
        );
        
        // Relative redirects shouldn't match (handled cleanly by browser)
        assert_eq!(
            rewrite_location_header("/about", "saif.github.io", "saif.kin"),
            None
        );
    }
}
