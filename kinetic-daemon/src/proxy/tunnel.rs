//! TLS termination handler and inner HTTP connection dispatcher for CONNECT proxy tunnels.

use super::*;

/// Handles an HTTP CONNECT request, upgrading the connection, performing TLS termination,
/// and routing inner HTTP traffic to the appropriate backend.
///
/// # Errors
/// Returns a `ProxyError` if the TLS handshake fails or the inner HTTP request cannot be served.
pub async fn handle_connect_req(
    raw_host: String,
    apex_domain: String,
    upgraded: hyper::upgrade::Upgraded,
    root_ca: Arc<RootCa>,
    leaf_cache: Arc<Mutex<LeafCertCache>>,
    network_client: Arc<NetworkClient>,
    config: Arc<kinetic_core::config::KineticConfig>,
    node_peer_id: String,
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
        let config_clone = Arc::clone(&config);
        let peer_id_clone = node_peer_id.clone();
        async move {
            match forward_to_backend_direct(req, &d, &nc, config_clone, &peer_id_clone).await {
                Ok(resp) => Ok::<_, std::convert::Infallible>(resp),
                Err(e) => {
                    warn!("Forwarding error: {}", e);
                    Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(axum::body::Body::from(format!("Backend Error: {}", e)))
                        .unwrap_or_else(|_| {
                            Response::new(axum::body::Body::from("Internal Proxy Error"))
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
