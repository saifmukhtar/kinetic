//! HTTP request routing, CNAME recursion, IPFS gateway proxying, P2P peer forwarding, and SSRF loop protection.

use super::*;
use kinetic_core::types::DnsZoneExt;
/// Handles an incoming HTTP or HTTPS (CONNECT) proxy request, determining how to route it.
pub async fn handle_proxy_request(
    req: Request<Incoming>,
    client: NetworkClient,
    root_ca: Arc<RootCa>,
    leaf_cache: Arc<Mutex<LeafCertCache>>,
    config: Arc<kinetic_core::config::KineticConfig>,
    node_peer_id: String,
) -> Result<Response<axum::body::Body>, std::convert::Infallible> {
    let loop_header = req.headers().get("x-kinetic-loop-protect").and_then(|h| h.to_str().ok());
    if loop_header == Some(&node_peer_id) {
        return Ok(Response::builder()
            .status(StatusCode::LOOP_DETECTED)
            .body(axum::body::Body::from("Proxy Loop Detected"))
            .unwrap_or_else(|_| Response::new(axum::body::Body::from("Internal Proxy Error"))));
    }

    if req.method() == Method::CONNECT {
        let raw_host = req.uri().host().unwrap_or("").to_string();
        let domain_name = kinetic_core::types::normalize_name(&raw_host);

        if !domain_name.ends_with(kinetic_core::constants::TLD_SUFFIX) {
            // Reject non-.kin CONNECT — we are not a general proxy
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(axum::body::Body::from(format!(
                    "Kinetic proxy only handles {} domains",
                    kinetic_core::constants::TLD_SUFFIX
                )))
                .unwrap_or_else(|_| {
                    Response::new(axum::body::Body::from("Internal Proxy Error"))
                }));
        }

        // Acknowledge tunnel to browser
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = handle_connect(
                        raw_host,
                        domain_name,
                        upgraded,
                        root_ca,
                        leaf_cache,
                        Arc::new(client),
                        Arc::clone(&config),
                        node_peer_id.clone(),
                    )
                    .await
                    {
                        error!("CONNECT tunnel error: {}", e);
                    }
                }
                Err(e) => error!("Upgrade error: {}", e),
            }
        });

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(axum::body::Body::empty())
            .unwrap_or_else(|_| Response::new(axum::body::Body::from("Internal Proxy Error"))));
    }

    // Fallback logic for plain HTTP .kin requests
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(':').next().unwrap_or("").to_string())
        .unwrap_or_default();

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    let host_name = kinetic_core::types::normalize_name(&host);
    if !host_name.ends_with(kinetic_core::constants::TLD_SUFFIX) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(axum::body::Body::from(
                "Only .kin domains are supported by this proxy",
            ))
            .unwrap_or_else(|_| Response::new(axum::body::Body::from("Internal Proxy Error"))));
    }

    info!("Proxying plain HTTP request for {} -> {}", host_name, path);

    // Resolve PeerId/IP from DHT
    match forward_to_backend_direct(req, &host_name, &client, Arc::clone(&config), &node_peer_id).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            warn!("Proxy request failed: {}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(axum::body::Body::from(format!("Proxy Error: {}", e)))
                .unwrap_or_else(|_| Response::new(axum::body::Body::from("Internal Proxy Error"))))
        }
    }
}

/// Forwards an HTTP request directly to a backend service by resolving the `.kin` domain to an IP or PeerId.
pub async fn forward_to_backend_direct(
    req: Request<Incoming>,
    domain: &str,
    network_client: &NetworkClient,
    config: Arc<kinetic_core::config::KineticConfig>,
    node_peer_id: &str,
) -> Result<Response<axum::body::Body>, ProxyError> {
    let mut current_domain = domain.to_string();
    let mut target_str = String::new();
    let mut recursion_count = 0;

    while recursion_count < 10 {
        recursion_count += 1;
        let apex_domain = kinetic_core::types::extract_apex_name(&current_domain);

        // Resolve via DHT directly — NOT via system DNS
        let payload = network_client
            .resolve_redundant_payload(&apex_domain)
            .await
            .map_err(|_| ProxyError::NameNotFound(apex_domain.clone()))?;

        // The DHT stores the full Reveal JSON (set by api.rs via serde_json::to_vec(&reveal)).
        // We must deserialize it and extract reveal.payload — the same pattern the DNS handler uses.
        let record = serde_json::from_slice::<kinetic_core::types::NameRecord>(&payload)
            .map_err(|_| ProxyError::InvalidPayload)?;

        let zone = match kinetic_core::types::DnsZone::parse_payload(record.payload()) {
            Ok(z) => z,
            Err(e) => {
                tracing::warn!("Proxy Error: Invalid DnsZone payload: {}", e);
                return Err(ProxyError::InvalidPayload);
            }
        };

        let mut subdomain = if current_domain == apex_domain {
            "@".to_string()
        } else {
            let trimmed = current_domain.trim_end_matches(&format!(".{}", apex_domain));
            trimmed.trim_end_matches('.').to_string()
        };
        if subdomain.is_empty() {
            subdomain = "@".to_string();
        }

        tracing::info!(
            "Proxy looking for subdomain '{}' in zone: {:?}",
            subdomain,
            zone
        );

        let records = match zone.records.get(&subdomain) {
            Some(r) => r,
            None => {
                tracing::warn!("Proxy Error: Subdomain '{}' not found in zone", subdomain);
                return Err(ProxyError::NameNotFound(current_domain.clone()));
            }
        };

        let mut cname_target = None;
        for record in records {
            tracing::info!("Proxy considering record: {:?}", record);
            match record {
                kinetic_core::types::DnsRecord::A(ip) => {
                    target_str = ip.to_string();
                    break;
                }
                kinetic_core::types::DnsRecord::AAAA(ip) => {
                    target_str = ip.to_string();
                    break;
                }
                kinetic_core::types::DnsRecord::TXT(_) => {
                    continue; // Do NOT parse TXT records as IPs for proxying
                }
                kinetic_core::types::DnsRecord::PeerId(peer_id) => {
                    target_str = peer_id.clone();
                    break;
                }
                kinetic_core::types::DnsRecord::CNAME(target) => {
                    cname_target = Some(target.clone());
                    break;
                }
                kinetic_core::types::DnsRecord::IPFS(cid) => {
                    target_str = format!("ipfs://{}", cid);
                    break;
                }
                _ => continue,
            }
        }

        if !target_str.is_empty() {
            break; // Found our final target!
        }

        if let Some(target) = cname_target {
            if target.ends_with(kinetic_core::constants::TLD_SUFFIX) {
                tracing::info!("CNAME recursion from {} to {}", current_domain, target);
                current_domain = target;
                continue;
            } else {
                tracing::warn!(
                    "CNAME points to external domain {} which proxy cannot resolve",
                    target
                );
                return Err(ProxyError::NameNotFound(current_domain.clone()));
            }
        }

        break;
    }

    if target_str.is_empty() {
        return Err(ProxyError::NameNotFound(domain.to_string()));
    }

    let ip_str = target_str;

    if ip_str.starts_with("ipfs://") {
        let cid = ip_str.trim_start_matches("ipfs://");
        let gateway = config.daemon.ipfs_gateway.trim_end_matches('/');
        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
            .trim_start_matches('/');

        let ipfs_url = if path.is_empty() {
            format!("{}/{}", gateway, cid)
        } else {
            format!("{}/{}/{}", gateway, cid, path)
        };

        tracing::info!("Proxying IPFS request to gateway: {}", ipfs_url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let mut out_req = client.request(req.method().clone(), &ipfs_url);

        for (name, value) in req.headers() {
            // Strip HOST so the gateway handles it properly
            if name != hyper::header::HOST {
                out_req = out_req.header(name, value);
            }
        }

        let backend_resp = out_req.send().await?;
        let mut resp_builder = Response::builder().status(backend_resp.status());
        for (name, value) in backend_resp.headers() {
            if name.as_str().to_lowercase() == "strict-transport-security" {
                continue; // Strip HSTS
            }
            resp_builder = resp_builder.header(name, value);
        }

        let body_stream = backend_resp.bytes_stream();
        let body = axum::body::Body::from_stream(body_stream);
        return Ok(resp_builder.body(body)?);
    }

    // Validate it is actually a routable IP or PeerId
    let is_ip_or_socket = ip_str.parse::<std::net::IpAddr>().is_ok()
        || ip_str.parse::<std::net::SocketAddr>().is_ok();

    if is_ip_or_socket {
        // Prevent SSRF: Do not proxy to loopback, private, or multicast networks!
        let ip_addr = if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
            ip
        } else if let Ok(sa) = ip_str.parse::<std::net::SocketAddr>() {
            sa.ip()
        } else {
            return Err(ProxyError::NameNotFound(domain.to_string()));
        };

        // Extract the original requested port (default to 80 if HTTP)
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

        // Case 199: Prevent infinite proxy loops even in Dev Mode
        // This check must happen before the dev mode bypass to protect the daemon's internal ports.
        if (ip_addr.is_loopback() || ip_addr.is_unspecified())
            && (original_port == config.daemon.proxy_port
                || original_port == config.daemon.api_port
                || original_port == config.daemon.dns_port
                || original_port == config.daemon.backend_port
                || original_port == config.network.daemon_port
                || original_port == config.daemon.pac_port)
        // PAC port
        {
            return Err(ProxyError::Other(
                "Proxy Loop Detected: Cannot proxy to daemon's internal ports.".to_string(),
            ));
        }

        let is_ssrf = is_ssrf_risk(ip_addr) || ip_addr.is_unspecified();

        if is_ssrf && !kinetic_core::config::is_dev_mode() {
            return Err(ProxyError::Other("SSRF Protection: Cannot proxy to loopback or private IPs. (Use Dev Mode to bypass)".to_string()));
        } else if is_ssrf {
            tracing::warn!(
                "DEV MODE: Forwarding to private IP {}. This would be blocked in production.",
                ip_addr
            );
        }

        // Auto-upgrade public IPs to HTTPS and port 443
        let scheme = if is_ssrf { "http" } else { "https" };
        let port = if !is_ssrf && original_port == 80 { 443 } else { original_port };

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
            req.uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/")
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .no_proxy()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let mut backend_req = client.request(req.method().clone(), &backend_url);

        // Forward original headers, set Host to .kin domain
        for (name, value) in req.headers() {
            if name != hyper::header::HOST {
                backend_req = backend_req.header(name, value);
            }
        }
        backend_req = backend_req.header("Host", domain);
        backend_req = backend_req.header("X-Kinetic-Loop-Protect", node_peer_id);

        let backend_resp = backend_req.send().await?;

        // Build response, stripping HSTS
        let mut resp_builder = Response::builder().status(backend_resp.status());

        for (name, value) in backend_resp.headers() {
            // Strip HSTS — prevents browser from caching upgrade directives
            if name.as_str().to_lowercase() == "strict-transport-security" {
                continue;
            }
            resp_builder = resp_builder.header(name, value);
        }

        let body_stream = backend_resp.bytes_stream();
        let body = axum::body::Body::from_stream(body_stream);
        Ok(resp_builder.body(body)?)
    } else if let Ok(mut peer_id) = ip_str.parse::<libp2p::PeerId>() {
        // Transparently resolve HostRoutingRecord if this PeerId is a static infrastructure node
        if let Ok(Some(record)) = network_client
            .resolve_host_routing_record(&peer_id.to_string())
            .await
        {
            tracing::info!(
                "Resolved HostRoutingRecord for static Host ID {}: dynamically routing to Ephemeral Peer ID {}",
                peer_id, record.current_peer_id
            );
            if let Ok(dynamic_peer_id) = record.current_peer_id.parse::<libp2p::PeerId>() {
                peer_id = dynamic_peer_id;
            } else {
                tracing::warn!(
                    "HostRoutingRecord returned invalid PeerId: {}",
                    record.current_peer_id
                );
            }
        } else {
            tracing::debug!("No dynamic route found for {}, routing directly.", peer_id);
        }

        // Forward to the libp2p PeerId via P2P network

        let mut headers = Vec::new();
        let strip_req_headers = [
            "authorization",
            "cookie",
            "x-api-key",
            "proxy-authorization",
        ];
        for (name, value) in req.headers() {
            let name_lower = name.as_str().to_lowercase();
            if !strip_req_headers.contains(&name_lower.as_str()) && name_lower != "host" {
                if let Ok(val_str) = value.to_str() {
                    headers.push((name_lower.into(), val_str.into()));
                }
            }
        }
        headers.push(("host".into(), domain.into()));

        let method = req.method().as_str().to_string();
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        use http_body_util::BodyExt;
        let mut body_bytes = Vec::new();
        let mut body_stream = req.into_body();
        while let Some(chunk) = body_stream.frame().await {
            let frame = chunk.map_err(|_| ProxyError::InvalidPayload)?;
            if let Ok(data) = frame.into_data() {
                body_bytes.extend_from_slice(&data);
                if body_bytes.len() > kinetic_core::constants::LIMITS_PROXY_MAX_BODY_BYTES {
                    tracing::warn!("Blocked P2P proxy request payload exceeding 5MB limit");
                    return Err(ProxyError::InvalidPayload);
                }
            }
        }

        let proxy_req = kinetic_network::ProxyRequest {
            method: method.into(),
            path: path.into(),
            headers,
            body: bytes::Bytes::from(body_bytes),
        };

        let proxy_resp = network_client
            .send_proxy_request(peer_id, proxy_req)
            .await
            .map_err(|e| {
                tracing::error!("send_proxy_request failed: {:?}", e);
                ProxyError::InvalidPayload
            })?;

        let mut resp_builder = Response::builder().status(proxy_resp.status);

        let strip_resp_headers = ["strict-transport-security", "public-key-pins"];
        for (name, value) in proxy_resp.headers {
            if strip_resp_headers.contains(&name.to_lowercase().as_str()) {
                continue;
            }
            resp_builder = resp_builder.header(name.as_ref(), value.as_ref());
        }

        Ok(resp_builder.body(axum::body::Body::from(proxy_resp.body))?)
    } else {
        warn!(
            "Payload for {} is neither an IP address, SocketAddr, nor PeerId (got {:?})",
            domain, ip_str
        );
        Err(ProxyError::InvalidPayload)
    }
}
