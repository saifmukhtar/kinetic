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

    // 1. Manually resolve the target domain to an IP using the OS resolver.
    // We append :443 because we will strictly use HTTPS for external Web2 domains.
    let lookup_string = format!("{}:443", target_domain);
    let mut addrs = match lookup_host(&lookup_string).await {
        Ok(a) => a,
        Err(e) => {
            warn!("Web2 Bridge: Failed to resolve {}: {}", target_domain, e);
            return Err(ProxyError::NameNotFound(target_domain.to_string()));
        }
    };

    // Grab the first available IP
    let socket_addr = match addrs.next() {
        Some(addr) => addr,
        None => {
            warn!("Web2 Bridge: No IPs found for {}", target_domain);
            return Err(ProxyError::NameNotFound(target_domain.to_string()));
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
            "Web2 Bridge SSRF Blocked: {} resolved to a dangerous IP ({}). Reason: {}",
            target_domain, ip_addr, reason
        );
        return Err(ProxyError::SecurityViolation(format!(
            "Web2 Bridge target resolved to a dangerous IP. Reason: {}",
            reason
        )));
    }

    // 3. Build the reqwest client securely.
    // By using `.resolve()`, we force reqwest to use the EXACT IP we just checked.
    // This makes DNS Rebinding SSRF attacks impossible, as reqwest won't re-resolve the domain.
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .no_proxy()
        // Force the resolved and verified IP for the target domain
        .resolve(target_domain, socket_addr)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| {
            warn!("Web2 Bridge: Failed to build HTTP client: {}", e);
            ProxyError::Other("Internal Proxy Error".to_string())
        })?;

    // Extract the original path and query
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");

    let backend_url = format!("https://{}{}", target_domain, path);

    let mut backend_req = client.request(req.method().clone(), &backend_url);

    // 4. Forward headers, but heavily override the Host header to trick the Web2 host
    for (name, value) in req.headers() {
        if name != hyper::header::HOST {
            backend_req = backend_req.header(name, value);
        }
    }
    // Set the Host header to the Web2 domain so GitHub/Vercel recognize it
    backend_req = backend_req.header("Host", target_domain);

    // Execute the request
    let backend_resp = backend_req.send().await.map_err(|e| {
        warn!("Web2 Bridge: Request to {} failed: {}", target_domain, e);
        ProxyError::Other("Web2 Backend Connection Failed".to_string())
    })?;

    // 5. Build the response back to the user
    let mut resp_builder = Response::builder().status(backend_resp.status());

    for (name, value) in backend_resp.headers() {
        // Strip HSTS to prevent the browser from caching TLS directives for the .kin domain
        if name.as_str().to_lowercase() == "strict-transport-security" {
            continue;
        }
        resp_builder = resp_builder.header(name, value);
    }

    let body_stream = backend_resp.bytes_stream();
    let body = axum::body::Body::from_stream(body_stream);

    resp_builder.body(body).map_err(|e| {
        warn!("Web2 Bridge: Failed to build response body: {}", e);
        ProxyError::Other("Failed to construct response".to_string())
    })
}
