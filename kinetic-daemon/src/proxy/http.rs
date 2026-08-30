//! HTTP request routing, CNAME recursion, IPFS gateway proxying, P2P peer forwarding, and SSRF loop protection.

use super::*;
use kinetic_core::types::NrsZoneExt;
/// Handles an incoming HTTP or HTTPS (CONNECT) proxy request, determining how to route it.
pub async fn handle_proxy_request(
    req: Request<Incoming>,
    client: NetworkClient,
    root_ca: Arc<RootCa>,
    leaf_cache: Arc<Mutex<LeafCertCache>>,
    config: Arc<kinetic_core::config::KineticConfig>,
    node_peer_id: String,
) -> Result<Response<axum::body::Body>, std::convert::Infallible> {
    let loop_header = req
        .headers()
        .get("x-kinetic-loop-protect")
        .and_then(|h| h.to_str().ok());
    if loop_header == Some(&node_peer_id) {
        return Ok(Response::builder()
            .status(StatusCode::LOOP_DETECTED)
            .body(axum::body::Body::from("Proxy Loop Detected"))
            .unwrap_or_else(|_| Response::new(axum::body::Body::from("Internal Proxy Error"))));
    }

    if req.method() == Method::CONNECT {
        let raw_host = req.uri().host().unwrap_or("").to_string();
        let full_name = kinetic_core::types::normalize_name(&raw_host);

        if !full_name.ends_with(kinetic_core::constants::NSP_SUFFIX) {
            // Reject non-.kin CONNECT — we are not a general proxy
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(axum::body::Body::from(format!(
                    "Kinetic proxy only handles {} names",
                    kinetic_core::constants::NSP_SUFFIX
                )))
                .unwrap_or_else(|_| {
                    Response::new(axum::body::Body::from("Internal Proxy Error"))
                }));
        }

        // Acknowledge tunnel to browser
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = handle_connect_req(
                        raw_host,
                        full_name,
                        upgraded,
                        root_ca,
                        leaf_cache,
                        Arc::new(client),
                        Arc::clone(&config),
                        node_peer_id.clone(),
                    )
                    .await
                    {
                        error!("KIN-PRX-005: CONNECT tunnel error: {}", e);
                    }
                }
                Err(e) => error!("KIN-PRX-006: Upgrade error: {}", e),
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
    if !host_name.ends_with(kinetic_core::constants::NSP_SUFFIX) {
        tracing::warn!("KIN-PRX-004: Rejected proxy request for non-.kin name: {}", host_name);
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(axum::body::Body::from(
                "Only .kin names are supported by this proxy",
            ))
            .unwrap_or_else(|_| Response::new(axum::body::Body::from("Internal Proxy Error"))));
    }

    info!("Proxying plain HTTP request for {} -> {}", host_name, path);

    // Resolve PeerId/IP from DHT
    match forward_to_backend_direct(req, &host_name, &client, Arc::clone(&config), &node_peer_id)
        .await
    {
        Ok(resp) => Ok(resp),
        Err(e) => {
            warn!("KIN-PRX-007: Proxy request failed: {}", e);
            let status = match e {
                ProxyError::SecurityViolation(_) => StatusCode::FORBIDDEN,
                ProxyError::PeerUnreachable(_) => StatusCode::GATEWAY_TIMEOUT,
                ProxyError::NameNotFound(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::BAD_GATEWAY,
            };
            Ok(Response::builder()
                .status(status)
                .body(axum::body::Body::from(format!("Proxy Error: {}", e)))
                .unwrap_or_else(|_| Response::new(axum::body::Body::from("Internal Proxy Error"))))
        }
    }
}

/// Forwards an HTTP request directly to a backend service by resolving the `.kin` name to an IP or PeerId.
pub async fn forward_to_backend_direct(
    req: Request<Incoming>,
    name: &str,
    network_client: &NetworkClient,
    config: Arc<kinetic_core::config::KineticConfig>,
    node_peer_id: &str,
) -> Result<Response<axum::body::Body>, ProxyError> {
    let mut current_name = name.to_string();
    let mut target_str = String::new();
    let mut recursion_count = 0;

    while recursion_count < 10 {
        recursion_count += 1;
        let apex_name = kinetic_core::types::extract_apex_name(&current_name);

        // Resolve via DHT directly — NOT via system DNS
        let payload = network_client
            .resolve_redundant_payload(&apex_name)
            .await
            .map_err(|e| {
                tracing::warn!("KIN-PRX-008: DHT resolution failed for apex name '{}': {}", apex_name, e);
                ProxyError::NameNotFound(apex_name.clone())
            })?;

        // The DHT stores the full Reveal JSON (set by api.rs via serde_json::to_vec(&reveal)).
        // We must deserialize it and extract reveal.payload — the same pattern the DNS handler uses.
        let record = serde_json::from_slice::<kinetic_core::types::NameRecord>(&payload)
            .map_err(|e| {
                tracing::warn!("KIN-PRX-010: Failed to deserialize NameRecord JSON from DHT for '{}': {}", apex_name, e);
                ProxyError::InvalidPayload
            })?;

        use kinetic_verify::signatures::VerifySignature;
        if !kinetic_core::config::is_dev_mode() {
            if let Err(e) = record.verify_signature(kinetic_core::constants::NETWORK_SALT) {
                tracing::warn!("KIN-PRX-009: Proxy Error: Security violation! NameRecord signature verification failed (Spoofed DHT response): {:?}", e);
                return Err(ProxyError::SecurityViolation("NameRecord signature verification failed".to_string()));
            }
        }

        let zone = match kinetic_core::types::NrsZone::parse_payload(record.payload()) {
            Ok(z) => z,
            Err(e) => {
                tracing::warn!("KIN-PRX-011: Proxy Error: Invalid NrsZone payload: {}", e);
                return Err(ProxyError::InvalidPayload);
            }
        };

        let mut subname = if current_name == apex_name {
            "@".to_string()
        } else {
            let trimmed = current_name.trim_end_matches(&format!(".{}", apex_name));
            trimmed.trim_end_matches('.').to_string()
        };
        if subname.is_empty() {
            subname = "@".to_string();
        }

        tracing::info!(
            "Resolved Zone for {}. Looking for subname '{}'",
            apex_name,
            subname
        );

        let records = match zone.records.get(&subname) {
            Some(r) => r,
            None => {
                tracing::warn!("KIN-PRX-012: Proxy Error: Subname '{}' not found in zone", subname);
                return Err(ProxyError::NameNotFound(current_name.clone()));
            }
        };

        let mut cname_target = None;
        for record in records {
            tracing::info!("Proxy considering record: {:?}", record);
            match record {
                kinetic_core::types::NrsRecord::A(ip) => {
                    target_str = ip.to_string();
                    break;
                }
                kinetic_core::types::NrsRecord::AAAA(ip) => {
                    target_str = ip.to_string();
                    break;
                }
                kinetic_core::types::NrsRecord::TXT(_) => {
                    continue; // Do NOT parse TXT records as IPs for proxying
                }
                kinetic_core::types::NrsRecord::PeerId(peer_id) => {
                    target_str = peer_id.clone();
                    break;
                }
                kinetic_core::types::NrsRecord::CNAME(target) => {
                    cname_target = Some(target.clone());
                    break;
                }
                kinetic_core::types::NrsRecord::IPFS(cid) => {
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
            if target.ends_with(kinetic_core::constants::NSP_SUFFIX) {
                tracing::info!("CNAME recursion from {} to {}", current_name, target);
                current_name = target;
                continue;
            } else {
                tracing::info!(
                    "CNAME points to external Web2 domain {}. Handing off to Web2 Bridge.",
                    target
                );
                return crate::proxy::web2_bridge::forward_to_web2_backend(req, &target).await;
            }
        }

        break;
    }

    if target_str.is_empty() {
        tracing::warn!("KIN-PRX-013: No routable targets found in NrsZone for name '{}'", name);
        return Err(ProxyError::NameNotFound(name.to_string()));
    }

    let ip_str = target_str;

    if ip_str.starts_with("ipfs://") {
        let cid = ip_str.trim_start_matches("ipfs://");
        return crate::proxy::route_ipfs::forward_to_ipfs(req, Arc::clone(&config), cid).await;
    }

    // Validate it is actually a routable IP or PeerId
    let is_ip_or_socket = ip_str.parse::<std::net::IpAddr>().is_ok()
        || ip_str.parse::<std::net::SocketAddr>().is_ok();

    if is_ip_or_socket {
        return crate::proxy::route_ip::forward_to_ip(req, name, &ip_str, node_peer_id, Arc::clone(&config)).await;
    } else if let Ok(peer_id) = ip_str.parse::<libp2p::PeerId>() {
        return crate::proxy::route_p2p::forward_to_p2p(req, name, peer_id, network_client).await;
    } else {
        tracing::warn!(
            "KIN-PRX-014: Unrecognized target format in DHT payload for '{}': {:?}",
            name, ip_str
        );
        Err(ProxyError::InvalidPayload)
    }
}
