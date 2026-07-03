use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use kinetic_network::{NetworkClient, ProxyRequest, ProxyResponse};

fn is_ssrf_risk(ip: std::net::IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // 100.64.0.0/10 (CGNAT / Cloud Metadata)
            if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 {
                return true;
            }
            // 172.16.0.0/12
            if octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 {
                return true;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 169.254.0.0/16 (Link-local)
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            // 192.0.2.0/24 (TEST-NET-1)
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
                return true;
            }
            // 198.51.100.0/24 (TEST-NET-2)
            if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
                return true;
            }
            // 203.0.113.0/24 (TEST-NET-3)
            if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
                return true;
            }
            // 240.0.0.0/4 (Reserved)
            if (octets[0] & 0b1111_0000) == 240 {
                return true;
            }
            false
        }
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            // fc00::/7 (Unique local)
            if (segments[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // fe80::/10 (Link-local)
            if (segments[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            false
        }
    }
}

use crate::ca::{CaError, LeafCertCache, RootCa};

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("Name Not Found: {0}")]
    NameNotFound(String),
    #[error("Invalid Payload")]
    InvalidPayload,
    #[error("Hyper Error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("Reqwest Error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CA Error: {0}")]
    Ca(#[from] CaError),
    #[error("HTTP Error: {0}")]
    Http(#[from] hyper::http::Error),
    #[error("Other Error: {0}")]
    Other(String),
}

pub async fn start_proxy_server(
    client: NetworkClient,
    port: u16,
    root_ca: Arc<RootCa>,
    leaf_cache: Arc<Mutex<LeafCertCache>>,
) -> anyhow::Result<()> {
    // Case 198: IPv6 Only Network Support
    let addr = format!("127.0.0.1:{}", port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(
                "Failed to bind Proxy to 127.0.0.1, trying IPv6 loopback [::1] (Case 198): {}",
                e
            );
            TcpListener::bind(format!("[::1]:{}", port)).await?
        }
    };

    let actual_addr = listener.local_addr()?;
    info!(
        "Local HTTP Proxy Server successfully bound and listening on http://{}",
        actual_addr
    );

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let client_clone = client.clone();
        let ca_clone = Arc::clone(&root_ca);
        let cache_clone = Arc::clone(&leaf_cache);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        handle_proxy_request(
                            req,
                            client_clone.clone(),
                            Arc::clone(&ca_clone),
                            Arc::clone(&cache_clone),
                        )
                    }),
                )
                .with_upgrades()
                .await
            {
                warn!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn handle_proxy_request(
    req: Request<Incoming>,
    client: NetworkClient,
    root_ca: Arc<RootCa>,
    leaf_cache: Arc<Mutex<LeafCertCache>>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    if req.method() == Method::CONNECT {
        let raw_host = req.uri().host().unwrap_or("").to_string();
        let domain_name = kinetic_core::types::normalize_name(&raw_host);

        if !domain_name.ends_with(".kin") {
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
    if !host_name.ends_with(".kin") {
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from(
                "Only .kin domains are supported by this proxy",
            )))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Internal Proxy Error")))));
    }

    info!("Proxying plain HTTP request for {} -> {}", host_name, path);

    // Resolve PeerId/IP from DHT
    match forward_to_backend_direct(req, &host_name, &client).await {
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

async fn handle_connect(
    raw_host: String,
    apex_domain: String,
    upgraded: hyper::upgrade::Upgraded,
    root_ca: Arc<RootCa>,
    leaf_cache: Arc<Mutex<LeafCertCache>>,
    network_client: Arc<NetworkClient>,
) -> Result<(), ProxyError> {
    // 1. Get leaf cert for this domain (uses the full requested subdomain!)
    let server_config = {
        let mut cache = leaf_cache.lock().await;
        cache.get_or_create(&raw_host, &root_ca)?
    }; // Lock released here — important

    // 2. TLS handshake with browser
    let acceptor = TlsAcceptor::from(server_config);
    let tls_stream = acceptor.accept(TokioIo::new(upgraded)).await?;

    // 3. Run a second HTTP service over the decrypted stream
    let network_client = Arc::clone(&network_client);

    let service = service_fn(move |req: Request<Incoming>| {
        let nc = Arc::clone(&network_client);
        let d = apex_domain.clone();
        async move {
            match forward_to_backend_direct(req, &d, &nc).await {
                Ok(resp) => Ok::<_, std::convert::Infallible>(resp),
                Err(e) => {
                    warn!("Forwarding error: {}", e);
                    Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from(format!("Backend Error: {}", e))))
                        .unwrap_or_else(|_| {
                            Response::new(Full::new(Bytes::from("Internal Proxy Error")))
                        }))
                }
            }
        }
    });

    // hyper 1.x
    http1::Builder::new()
        .serve_connection(TokioIo::new(tls_stream), service)
        .await?;

    Ok(())
}

async fn forward_to_backend_direct(
    req: Request<Incoming>,
    domain: &str,
    network_client: &NetworkClient,
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

    tracing::info!("Proxy looking for subdomain '{}' in zone: {:?}", subdomain, zone);

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
                target_str = ip.clone();
                break;
            }
            kinetic_core::types::DnsRecord::AAAA(ip) => {
                target_str = ip.clone();
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
        matches!(records.iter().find(|r| match r {
            kinetic_core::types::DnsRecord::A(s) | kinetic_core::types::DnsRecord::AAAA(s) => s == &ip_str,
            _ => false,
        }), Some(_))
    } else if let Ok(_sa) = ip_str.parse::<std::net::SocketAddr>() {
        matches!(records.iter().find(|r| match r {
            kinetic_core::types::DnsRecord::A(s) | kinetic_core::types::DnsRecord::AAAA(s) => s == &ip_str,
            _ => false,
        }), Some(_))
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
            let cfg = kinetic_core::config::KineticConfig::load();
            if ip_str.contains(&format!(":{}", cfg.daemon.proxy_port))
                || ip_str.contains(&format!(":{}", cfg.daemon.api_port))
                || ip_str.contains(&format!(":{}", cfg.daemon.dns_port))
                || ip_str.contains(&format!(":{}", cfg.daemon.backend_port))
                || ip_str.contains(&format!(":{}", cfg.network.p2p_port))
                || ip_str.contains(":16001") // PAC port
            {
                return Err(ProxyError::Other(
                    "Proxy Loop Detected: Cannot proxy to daemon's internal ports.".to_string(),
                ));
            }
        }

        if is_ssrf_risk(ip_addr) && !kinetic_core::config::is_dev_mode() {
            return Err(ProxyError::Other("SSRF Protection: Cannot proxy to loopback or private IPs. (Use Dev Mode to bypass)".to_string()));
        } else if is_ssrf_risk(ip_addr) {
            tracing::warn!("DEV MODE: Forwarding to private IP {}. This would be blocked in production.", ip_addr);
        }

        // Explicitly HTTP — no TLS to backend
        let backend_url = format!(
            "http://{}{}",
            ip_str,
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
        if let Ok(Some(record)) = network_client.resolve_host_routing_record(&peer_id.to_string()).await {
            tracing::info!(
                "Resolved HostRoutingRecord for static Host ID {}: dynamically routing to Ephemeral Peer ID {}",
                peer_id, record.current_peer_id
            );
            if let Ok(dynamic_peer_id) = record.current_peer_id.parse::<libp2p::PeerId>() {
                peer_id = dynamic_peer_id;
            } else {
                tracing::warn!("HostRoutingRecord returned invalid PeerId: {}", record.current_peer_id);
            }
        } else {
            tracing::debug!("No dynamic route found for {}, routing directly.", peer_id);
        }

        // Forward to the libp2p PeerId via P2P network

        let mut headers = std::collections::HashMap::new();
        let strip_req_headers = ["authorization", "cookie", "x-api-key", "proxy-authorization"];
        for (name, value) in req.headers() {
            let name_lower = name.as_str().to_lowercase();
            if !strip_req_headers.contains(&name_lower.as_str()) && name_lower != "host" {
                if let Ok(val_str) = value.to_str() {
                    headers.insert(name.as_str().to_string(), val_str.to_string());
                }
            }
        }
        headers.insert("Host".to_string(), domain.to_string());

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
            method,
            path,
            headers,
            body: body_bytes,
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
            "strict-transport-security", "public-key-pins",
            "x-frame-options", "content-security-policy",
            "x-content-type-options", "set-cookie", "location"
        ];
        for (name, value) in proxy_resp.headers {
            if strip_resp_headers.contains(&name.to_lowercase().as_str()) {
                continue;
            }
            resp_builder = resp_builder.header(&name, &value);
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

pub async fn handle_incoming_proxy_requests(
    client: NetworkClient,
    mut rx: tokio::sync::mpsc::Receiver<(
        ProxyRequest,
        libp2p::request_response::ResponseChannel<ProxyResponse>,
    )>,
    local_port: u16,
) {
    let reqwest_client = reqwest::Client::new();
    info!(
        "Listening for incoming P2P Proxy requests, forwarding to 127.0.0.1:{}",
        local_port
    );

    while let Some((req, channel)) = rx.recv().await {
        let reqwest_client = reqwest_client.clone();
        let client_clone = client.clone();

        tokio::spawn(async move {
            // Path traversal protection
            let safe_path = if req.path.contains("..") || !req.path.starts_with('/') {
                tracing::warn!("Blocked malicious P2P proxy path: {}", req.path);
                let _ = client_clone.send_proxy_response(channel, ProxyResponse {
                    status: 400,
                    headers: HashMap::new(),
                    body: b"Bad Request: Invalid Path".to_vec(),
                }).await;
                return;
            } else {
                &req.path
            };

            // Limit body size to 5MB to prevent OOM
            if req.body.len() > 5 * 1024 * 1024 {
                tracing::warn!("Blocked oversized P2P proxy request ({} bytes)", req.body.len());
                let _ = client_clone.send_proxy_response(channel, ProxyResponse {
                    status: 413,
                    headers: HashMap::new(),
                    body: b"Payload Too Large".to_vec(),
                }).await;
                return;
            }

            let url = format!("http://127.0.0.1:{}{}", local_port, safe_path);

            let method = match req.method.parse::<reqwest::Method>() {
                Ok(m) => m,
                Err(_) => {
                    tracing::warn!("Blocked invalid HTTP method: {}", req.method);
                    let _ = client_clone.send_proxy_response(channel, ProxyResponse {
                        status: 400,
                        headers: HashMap::new(),
                        body: b"Bad Request: Invalid Method".to_vec(),
                    }).await;
                    return;
                }
            };

            let mut builder = reqwest_client.request(method, &url);

            for (k, v) in req.headers {
                if k.to_lowercase() == "host" { continue; } // Never forward remote Host header
                builder = builder.header(k, v);
            }
            builder = builder.header("Host", format!("127.0.0.1:{}", local_port));
            builder = builder.body(req.body);

            let proxy_res = match builder.send().await {
                Ok(res) => {
                    let status = res.status().as_u16();
                    let mut res_headers = HashMap::new();
                    for (k, v) in res.headers() {
                        if let Ok(v_str) = v.to_str() {
                            res_headers.insert(k.as_str().to_string(), v_str.to_string());
                        }
                    }
                    let body = res.bytes().await.unwrap_or_default().to_vec();
                    ProxyResponse {
                        status,
                        headers: res_headers,
                        body,
                    }
                }
                Err(e) => {
                    warn!("Failed to forward request to local web server: {}", e);
                    ProxyResponse {
                        status: 502,
                        headers: HashMap::new(),
                        body: format!(
                            "Bad Gateway: Local web server not responding on port {}\nError: {}",
                            local_port, e
                        )
                        .into_bytes(),
                    }
                }
            };

            let _ = client_clone.send_proxy_response(channel, proxy_res).await;
        });
    }
}
