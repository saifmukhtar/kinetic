use super::*;
pub async fn handle_proxy_request(
    req: Request<Incoming>,
    client: NetworkClient,
    root_ca: Arc<RootCa>,
    leaf_cache: Arc<Mutex<LeafCertCache>>,
    config: Arc<kinetic_core::config::KineticConfig>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    if req.method() == Method::CONNECT {
        let raw_host = req.uri().host().unwrap_or("").to_string();
        let domain_name = kinetic_core::types::normalize_name(&raw_host);

        if !domain_name.ends_with(kinetic_core::types::DOT_TLD) {
            // Reject non-.kin CONNECT — we are not a general proxy
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from(
                    "Kinetic proxy only handles .kin domains",
                )))
                .unwrap_or_else(|_| {
                    Response::new(Full::new(Bytes::from("Internal Proxy Error")))
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
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Internal Proxy Error")))));
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
    if !host_name.ends_with(kinetic_core::types::DOT_TLD) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from(
                "Only .kin domains are supported by this proxy",
            )))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Internal Proxy Error")))));
    }

    info!("Proxying plain HTTP request for {} -> {}", host_name, path);

    // Resolve PeerId/IP from DHT
    match forward_to_backend_direct(req, &host_name, &client, Arc::clone(&config)).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            warn!("Proxy request failed: {}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!("Proxy Error: {}", e))))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Internal Proxy Error")))))
        }
    }
}

pub async fn forward_to_backend_direct(
    req: Request<Incoming>,
    domain: &str,
    network_client: &NetworkClient,
    config: Arc<kinetic_core::config::KineticConfig>,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    let apex_domain = kinetic_core::types::extract_apex_domain(domain);

    // Resolve via DHT directly — NOT via system DNS
    let payload = network_client
        .resolve_redundant_payload(&apex_domain)
        .await
        .map_err(|_| ProxyError::NameNotFound(apex_domain.clone()))?;

    // The DHT stores the full Reveal JSON (set by api.rs via serde_json::to_vec(&reveal)).
    // We must deserialize it and extract reveal.payload — the same pattern the DNS handler uses.
    let reveal = serde_json::from_slice::<kinetic_core::types::Reveal>(&payload)
        .map_err(|_| ProxyError::InvalidPayload)?;

    let zone = match kinetic_core::types::DnsZone::parse_payload(&reveal.payload) {
        Ok(z) => z,
        Err(e) => {
            tracing::warn!("Proxy Error: Invalid DnsZone payload: {}", e);
            return Err(ProxyError::InvalidPayload);
        }
    };

    let mut subdomain = if domain == apex_domain {
        "@".to_string()
    } else {
        let trimmed = domain.trim_end_matches(&format!(".{}", apex_domain));
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
            return Err(ProxyError::NameNotFound(domain.to_string()));
        }
    };

    let mut target_str = String::new();
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
            // Note: If CNAME points to another .kin, we'd need to resolve recursively here,
            // but for simplicity we only support direct resolution for proxy right now.
            _ => continue,
        }
    }

    if target_str.is_empty() {
        return Err(ProxyError::NameNotFound(domain.to_string()));
    }

    let ip_str = target_str;

    // Validate it is actually a routable IP or PeerId
    let is_ip_or_socket = if let Ok(_ip) = ip_str.parse::<std::net::IpAddr>() {
        // Double check it wasn't a TXT/PeerId record that just happens to be a valid IP
        records
            .iter()
            .find(|r| match r {
                kinetic_core::types::DnsRecord::A(s) => s.to_string() == ip_str,
                kinetic_core::types::DnsRecord::AAAA(s) => s.to_string() == ip_str,
                _ => false,
            })
            .is_some()
    } else if let Ok(_sa) = ip_str.parse::<std::net::SocketAddr>() {
        records
            .iter()
            .find(|r| match r {
                kinetic_core::types::DnsRecord::A(s) => s.to_string() == ip_str,
                kinetic_core::types::DnsRecord::AAAA(s) => s.to_string() == ip_str,
                _ => false,
            })
            .is_some()
    } else {
        false
    };

    if is_ip_or_socket {
        // Prevent SSRF: Do not proxy to loopback, private, or multicast networks!
        let ip_addr = if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
            ip
        } else if let Ok(sa) = ip_str.parse::<std::net::SocketAddr>() {
            sa.ip()
        } else {
            return Err(ProxyError::NameNotFound(domain.to_string()));
        };

        // Case 199: Prevent infinite proxy loops even in Dev Mode
        // This check must happen before the dev mode bypass to protect the daemon's internal ports.
        if ip_addr.is_loopback() || ip_addr.is_unspecified() {
            if ip_str.contains(&format!(":{}", config.daemon.proxy_port))
                || ip_str.contains(&format!(":{}", config.daemon.api_port))
                || ip_str.contains(&format!(":{}", config.daemon.dns_port))
                || ip_str.contains(&format!(":{}", config.daemon.backend_port))
                || ip_str.contains(&format!(":{}", config.network.daemon_port))
                || ip_str.contains(":16001")
            // PAC port
            {
                return Err(ProxyError::Other(
                    "Proxy Loop Detected: Cannot proxy to daemon's internal ports.".to_string(),
                ));
            }
        }

        if is_ssrf_risk(ip_addr) && !kinetic_core::config::is_dev_mode() {
            return Err(ProxyError::Other("SSRF Protection: Cannot proxy to loopback or private IPs. (Use Dev Mode to bypass)".to_string()));
        } else if is_ssrf_risk(ip_addr) {
            tracing::warn!(
                "DEV MODE: Forwarding to private IP {}. This would be blocked in production.",
                ip_addr
            );
        }

        // Explicitly HTTP — no TLS to backend
        let formatted_host = if ip_addr.is_ipv6() {
            format!("[{}]", ip_str)
        } else {
            ip_str.clone()
        };
        let backend_url = format!(
            "http://{}{}",
            formatted_host,
            req.uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/")
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
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

        let body = backend_resp.bytes().await?;
        Ok(resp_builder.body(Full::new(body))?)
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
                if body_bytes.len() > 5 * 1024 * 1024 {
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

        let strip_resp_headers = [
            "strict-transport-security",
            "public-key-pins",
        ];
        for (name, value) in proxy_resp.headers {
            if strip_resp_headers.contains(&name.to_lowercase().as_str()) {
                continue;
            }
            resp_builder = resp_builder.header(name.as_ref(), value.as_ref());
        }

        Ok(resp_builder.body(Full::new(bytes::Bytes::from(proxy_resp.body)))?)
    } else {
        warn!(
            "Payload for {} is neither an IP address, SocketAddr, nor PeerId (got {:?})",
            domain, ip_str
        );
        Err(ProxyError::InvalidPayload)
    }
}

