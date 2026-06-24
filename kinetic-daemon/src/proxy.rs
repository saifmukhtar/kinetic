use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::TokioIo;
use http_body_util::Full;
use tokio::net::TcpListener;
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn, error};

use kinetic_network::network::{NetworkClient, ProxyRequest, ProxyResponse};


use crate::ca::{RootCa, LeafCertCache, CaError};

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
}

pub async fn start_proxy_server(
    client: NetworkClient,
    port: u16,
    root_ca: Arc<RootCa>,
    leaf_cache: Arc<Mutex<LeafCertCache>>,
) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;
    info!("Local HTTP Proxy Server listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let client_clone = client.clone();
        let ca_clone = Arc::clone(&root_ca);
        let cache_clone = Arc::clone(&leaf_cache);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(move |req| {
                    handle_proxy_request(req, client_clone.clone(), Arc::clone(&ca_clone), Arc::clone(&cache_clone))
                }))
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
        let domain = req.uri().host()
            .unwrap_or("")
            .trim_end_matches('.')
            .to_string();

        if !domain.ends_with(".kin") {
            // Reject non-.kin CONNECT — we are not a general proxy
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from("Kinetic proxy only handles .kin domains")))
                .unwrap());
        }

        // Acknowledge tunnel to browser
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = handle_connect(
                        domain, upgraded, root_ca, leaf_cache, Arc::new(client)
                    ).await {
                        error!("CONNECT tunnel error: {}", e);
                    }
                }
                Err(e) => error!("Upgrade error: {}", e),
            }
        });

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    // Fallback logic for plain HTTP .kin requests
    let host = req.headers().get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(':').next().unwrap_or("").to_string());

    let path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/").to_string();

    let host_name = match host {
        Some(h) if h.ends_with(".kin") => format!("{}.", h),
        Some(h) if h.ends_with(".kin.") => h,
        _ => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Only .kin domains are supported by this proxy")))
                .unwrap());
        }
    };

    info!("Proxying plain HTTP request for {} -> {}", host_name, path);
    
    // Resolve PeerId/IP from DHT
    match forward_to_backend_direct(req, &host_name, &client).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            warn!("Proxy request failed: {}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!("Proxy Error: {}", e))))
                .unwrap())
        }
    }
}

async fn handle_connect(
    domain: String,
    upgraded: hyper::upgrade::Upgraded,
    root_ca: Arc<RootCa>,
    leaf_cache: Arc<Mutex<LeafCertCache>>,
    network_client: Arc<NetworkClient>,
) -> Result<(), ProxyError> {
    // 1. Get leaf cert for this domain
    let server_config = {
        let mut cache = leaf_cache.lock().await;
        cache.get_or_create(&domain, &root_ca)?
    }; // Lock released here — important

    // 2. TLS handshake with browser
    let acceptor = TlsAcceptor::from(server_config);
    let tls_stream = acceptor.accept(TokioIo::new(upgraded)).await?;

    // 3. Run a second HTTP service over the decrypted stream
    let network_client = Arc::clone(&network_client);
    let domain = format!("{}.", domain); // Add trailing dot for consistency
    
    let service = service_fn(move |req: Request<Incoming>| {
        let nc = Arc::clone(&network_client);
        let d = domain.clone();
        async move { 
            match forward_to_backend_direct(req, &d, &nc).await {
                Ok(resp) => Ok::<_, std::convert::Infallible>(resp),
                Err(e) => {
                    warn!("Forwarding error: {}", e);
                    Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from(format!("Backend Error: {}", e))))
                        .unwrap())
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
    // Resolve via DHT directly — NOT via system DNS
    let payload = network_client.resolve_redundant_payload(domain).await
        .map_err(|_| ProxyError::NameNotFound(domain.to_string()))?
        .ok_or_else(|| ProxyError::NameNotFound(domain.to_string()))?;

    // The DHT stores the full Reveal JSON (set by api.rs via serde_json::to_vec(&reveal)).
    // We must deserialize it and extract reveal.payload — the same pattern the DNS handler uses.
    let reveal = serde_json::from_slice::<kinetic_core::types::Reveal>(&payload)
        .map_err(|_| ProxyError::InvalidPayload)?;

    let ip_str = String::from_utf8(reveal.payload)
        .map_err(|_| ProxyError::InvalidPayload)?;

    // Validate it is actually a routable IP before constructing the URL
    if ip_str.parse::<std::net::IpAddr>().is_err() && ip_str.parse::<std::net::SocketAddr>().is_err() {
        warn!(
            "Payload for {} is not a valid IP address or SocketAddr (got {:?}) — \
             RegisterPeer routing via P2P not yet implemented",
            domain, ip_str
        );
        return Err(ProxyError::InvalidPayload);
    }

    // Explicitly HTTP — no TLS to backend
    let backend_url = format!("http://{}{}",
        ip_str,
        req.uri().path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // Redundant for HTTP but explicit
        .build()?;

    let mut backend_req = client.request(
        req.method().clone(),
        &backend_url,
    );

    // Forward original headers, set Host to .kin domain
    for (name, value) in req.headers() {
        if name != hyper::header::HOST {
            backend_req = backend_req.header(name, value);
        }
    }
    backend_req = backend_req.header("Host", domain);

    let backend_resp = backend_req.send().await?;

    // Build response, stripping HSTS
    let mut resp_builder = Response::builder()
        .status(backend_resp.status());

    for (name, value) in backend_resp.headers() {
        // Strip HSTS — prevents browser from caching upgrade directives
        if name.as_str().to_lowercase() == "strict-transport-security" {
            continue;
        }
        resp_builder = resp_builder.header(name, value);
    }

    let body = backend_resp.bytes().await?;
    Ok(resp_builder.body(Full::new(body))?)
}

pub async fn handle_incoming_proxy_requests(
    client: NetworkClient,
    mut rx: tokio::sync::mpsc::Receiver<(ProxyRequest, libp2p::request_response::ResponseChannel<ProxyResponse>)>,
    local_port: u16,
) {
    let reqwest_client = reqwest::Client::new();
    info!("Listening for incoming P2P Proxy requests, forwarding to 127.0.0.1:{}", local_port);

    while let Some((req, channel)) = rx.recv().await {
        let reqwest_client = reqwest_client.clone();
        let client_clone = client.clone();
        
        tokio::spawn(async move {
            let url = format!("http://127.0.0.1:{}{}", local_port, req.path);
            
            let mut builder = reqwest_client.request(
                req.method.parse().unwrap_or(reqwest::Method::GET),
                &url,
            );

            for (k, v) in req.headers {
                builder = builder.header(k, v);
            }
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
                    ProxyResponse { status, headers: res_headers, body }
                }
                Err(e) => {
                    warn!("Failed to forward request to local web server: {}", e);
                    ProxyResponse {
                        status: 502,
                        headers: HashMap::new(),
                        body: format!("Bad Gateway: Local web server not responding on port {}\nError: {}", local_port, e).into_bytes(),
                    }
                }
            };

            let _ = client_clone.send_proxy_response(channel, proxy_res).await;
        });
    }
}

