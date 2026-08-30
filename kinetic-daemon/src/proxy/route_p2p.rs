use super::*;
use hyper::{Request, Response, body::Incoming};

/// Tunnels the proxy request securely over the Libp2p network to the target PeerId.
///
/// **Architectural Note (Payload Limits):**
/// This P2P proxy relies on the `libp2p::request_response::cbor` protocol, which has 
/// strict, hardcoded message limits at the binary codec level:
/// - **Uploads (Requests):** Max 1MB (1,048,576 bytes)
/// - **Downloads (Responses):** Max 10MB (10,485,760 bytes)
/// 
/// If a decentralized `.kin` app attempts to serve or receive media larger than these limits, 
/// the Libp2p swarm will aggressively drop the packets. For large files, video streaming, 
/// or bulk data transfers, developers must use IPFS (`route_ipfs.rs`) instead of P2P routing.
pub async fn forward_to_p2p(
    req: Request<Incoming>,
    name: &str,
    mut peer_id: libp2p::PeerId,
    network_client: &NetworkClient,
) -> Result<Response<axum::body::Body>, ProxyError> {
    if let Ok(Some(record)) = network_client
        .resolve_host_routing_record(&peer_id.to_string())
        .await
    {
        tracing::info!(
            "Resolved HostRoutingRecord for static Host ID {}: dynamically routing to Ephemeral Peer ID {}",
            peer_id,
            record.current_peer_id
        );
        if let Ok(dynamic_peer_id) = record.current_peer_id.parse::<libp2p::PeerId>() {
            peer_id = dynamic_peer_id;
        } else {
            tracing::warn!(
                "KIN-P2P-020: HostRoutingRecord returned invalid PeerId: {}",
                record.current_peer_id
            );
        }
    } else {
        tracing::debug!("No dynamic route found for {}, routing directly.", peer_id);
    }

    let mut headers = Vec::new();
    let strip_req_headers = [
        "authorization",
        "cookie",
        "x-api-key",
        "proxy-authorization",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    for (name, value) in req.headers() {
        let name_lower = name.as_str().to_lowercase();
        if !strip_req_headers.contains(&name_lower.as_str())
            && name_lower != "host"
        {
            if let Ok(val_str) = value.to_str() {
                headers.push((name_lower.into(), val_str.into()));
            }
        }
    }
    headers.push(("host".into(), name.into()));

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
        let frame = chunk.map_err(|e| {
            tracing::warn!("KIN-P2P-022: Failed to read P2P request body stream: {}", e);
            ProxyError::InvalidPayload("KIN-P2P-022: Failed to read P2P request body stream".to_string())
        })?;
        if let Ok(data) = frame.into_data() {
            body_bytes.extend_from_slice(&data);
            
            // Note: libp2p::request_response::cbor hardcodes a 1MB limit (1024 * 1024)
            if body_bytes.len() > 1048576 {
                tracing::warn!("KIN-SEC-011: Blocked P2P proxy request payload exceeding 1MB Libp2p limit");
                return Err(ProxyError::InvalidPayload("KIN-SEC-011: Blocked P2P proxy request payload exceeding 1MB Libp2p limit".to_string()));
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
            tracing::error!("KIN-P2P-021: Libp2p tunnel failed to reach target peer: {}", e);
            ProxyError::PeerUnreachable(format!("KIN-P2P-021: P2P swarm could not deliver request to target peer: {}", e))
        })?;

    let mut resp_builder = Response::builder().status(proxy_resp.status);

    let strip_resp_headers = [
        "strict-transport-security", 
        "public-key-pins",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    for (name, value) in proxy_resp.headers {
        if strip_resp_headers.contains(&name.to_lowercase().as_str()) {
            continue;
        }
        resp_builder = resp_builder.header(name.as_ref(), value.as_ref());
    }

    let final_resp = resp_builder.body(axum::body::Body::from(proxy_resp.body)).map_err(|e| {
        tracing::error!("KIN-P2P-023: Failed to construct HTTP response from P2P tunnel data: {}", e);
        ProxyError::Other(format!("KIN-P2P-023: Failed to construct HTTP response from P2P tunnel data: {}", e))
    })?;

    Ok(final_resp)
}
