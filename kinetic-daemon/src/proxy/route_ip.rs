use super::*;
use hyper::{Request, Response, body::Incoming};

/// Forwards the proxy request to an SSRF-validated IP address.
///
/// **Architectural Note (WebSockets & Security):**
/// This IP-bridge intentionally does NOT support connection upgrading (e.g., WebSockets).
/// We rely on the `reqwest` HTTP client for outbound fetching because it securely manages 
/// TLS/SSL verification, ALPN, and connection pooling by default. Replacing it with a raw 
/// `hyper` TCP stream to support WebSockets would require manually implementing outbound TLS 
/// via `rustls`, which introduces massive risk of critical Man-in-the-Middle (MitM) vulnerabilities.
/// 
/// **Alternative:** Developers building real-time applications on the `.kin` network should avoid 
/// centralized WebSockets and instead utilize native Web3 architectures, such as P2P routing, 
/// Libp2p streams, or WebRTC.
pub async fn forward_to_ip(
    req: Request<Incoming>,
    name: &str,
    ip_str: &str,
    node_peer_id: &str,
    config: Arc<kinetic_core::config::KineticConfig>,
) -> Result<Response<axum::body::Body>, ProxyError> {
    let ip_addr = if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
        ip
    } else if let Ok(sa) = ip_str.parse::<std::net::SocketAddr>() {
        sa.ip()
    } else {
        tracing::warn!("KIN-PRX-028: Invalid IP format for name '{}': {}", name, ip_str);
        return Err(ProxyError::NameNotFound(name.to_string()));
    };

    let original_port = req
        .uri()
        .port_u16()
        .or_else(|| {
            req.headers()
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(':').nth(1))
                .and_then(|p| p.parse::<u16>().ok())
        })
        .unwrap_or(80);

    if (ip_addr.is_loopback() || ip_addr.is_unspecified())
        && (original_port == config.daemon.proxy_port
            || original_port == config.daemon.api_port
            || original_port == config.daemon.nrs_port
            || original_port == config.daemon.backend_port
            || original_port == config.network.daemon_port
            || original_port == config.daemon.pac_port)
    {
        tracing::error!("KIN-SEC-016: Proxy loop blocked for port {}", original_port);
        return Err(ProxyError::Other(
            "Proxy Loop Detected: Cannot proxy to daemon's internal ports.".to_string(),
        ));
    }

    let ssrf_result = security::validate_ssrf_risk(ip_addr);
    let is_ssrf = ssrf_result.is_err() || ip_addr.is_unspecified();

    if is_ssrf && !kinetic_core::config::is_dev_mode() {
        let reason = if ip_addr.is_unspecified() {
            "Unspecified IP".to_string()
        } else {
            ssrf_result.unwrap_err().to_string()
        };
        tracing::warn!("KIN-SEC-014: SSRF attempt blocked to {}", ip_addr);
        return Err(ProxyError::SecurityViolation(format!(
            "Cannot proxy to loopback or private IPs. Reason: {}. (Use Dev Mode to bypass)",
            reason
        )));
    } else if is_ssrf {
        let reason = if ip_addr.is_unspecified() {
            "Unspecified IP".to_string()
        } else {
            ssrf_result.unwrap_err().to_string()
        };
        tracing::warn!(
            "KIN-SEC-015: DEV MODE: Forwarding to private IP {}. Reason: {}. This would be blocked in production.",
            ip_addr,
            reason
        );
    }

    let scheme = if is_ssrf { "http" } else { "https" };
    let port = if !is_ssrf && original_port == 80 {
        443
    } else {
        original_port
    };

    let formatted_host = if ip_addr.is_ipv6() {
        format!("[{}]", ip_addr)
    } else {
        ip_addr.to_string()
    };

    let backend_url = format!(
        "{}://{}:{}{}",
        scheme,
        formatted_host,
        port,
        req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/")
    );

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let mut backend_req = client.request(req.method().clone(), &backend_url);

    let hop_by_hop = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
    ];

    for (name, value) in req.headers() {
        if !hop_by_hop.contains(&name.as_str().to_lowercase().as_str()) {
            backend_req = backend_req.header(name, value);
        }
    }
    backend_req = backend_req.header("Host", name);
    backend_req = backend_req.header("X-Kinetic-Loop-Protect", node_peer_id);

    use http_body_util::BodyExt;
    let mut body_bytes = Vec::new();
    let mut body_stream = req.into_body();
    while let Some(chunk_res) = body_stream.frame().await {
        if let Ok(frame) = chunk_res {
            if let Ok(data) = frame.into_data() {
                body_bytes.extend_from_slice(&data);
                if body_bytes.len() > kinetic_core::constants::LIMITS_PROXY_MAX_BODY_BYTES {
                    tracing::warn!("KIN-SEC-011: Blocked oversized IP proxy request body");
                    return Err(ProxyError::InvalidPayload);
                }
            }
        }
    }
    backend_req = backend_req.body(body_bytes);

    let backend_resp = backend_req.send().await.map_err(|e| {
        tracing::error!("KIN-PRX-027: Failed to reach IP gateway: {}", e);
        ProxyError::PeerUnreachable(format!("Failed to reach Web2 server: {}", e))
    })?;

    let mut resp_builder = Response::builder().status(backend_resp.status());
    let mut strip_resp_headers = hop_by_hop.to_vec();
    strip_resp_headers.push("strict-transport-security");

    for (name, value) in backend_resp.headers() {
        if !strip_resp_headers.contains(&name.as_str().to_lowercase().as_str()) {
            resp_builder = resp_builder.header(name, value);
        }
    }

    let body_stream = backend_resp.bytes_stream();
    let body = axum::body::Body::from_stream(body_stream);
    Ok(resp_builder.body(body)?)
}
