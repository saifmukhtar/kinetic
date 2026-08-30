//! Inbound P2P proxy request processor, security validator, and local backend forwarder.

use super::*;

/// Handles incoming P2P proxy requests from other nodes and forwards them to a local port.
pub async fn handle_incoming_proxy_requests(
    client: NetworkClient,
    mut rx: tokio::sync::mpsc::Receiver<(
        ProxyRequest,
        libp2p::request_response::ResponseChannel<ProxyResponse>,
    )>,
    bind_ip: String,
    local_port: u16,
) {
    let reqwest_client = reqwest::Client::new();
    info!(
        "Listening for incoming P2P Proxy requests, forwarding to {}:{}",
        bind_ip, local_port
    );

    while let Some((req, channel)) = rx.recv().await {
        let reqwest_client = reqwest_client.clone();
        let client_clone = client.clone();
        let bind_ip_clone = bind_ip.clone();

        tokio::spawn(async move {
            // Path traversal protection
            let decoded_path = percent_encoding::percent_decode_str(&req.path)
                .decode_utf8()
                .unwrap_or(std::borrow::Cow::Owned(req.path.to_string()));

            let safe_path = if decoded_path.contains("..") || !decoded_path.starts_with('/') {
                tracing::warn!("KIN-SEC-010: Blocked malicious P2P proxy path: {}", req.path);
                let _ = client_clone
                    .send_proxy_response(
                        channel,
                        ProxyResponse {
                            status: 400,
                            headers: Vec::new(),
                            body: bytes::Bytes::from_static(b"KIN-SEC-010: Bad Request: Invalid Path"),
                        },
                    )
                    .await;
                return;
            } else {
                &req.path
            };

            // Limit body size to 5MB to prevent OOM
            if req.body.len() > kinetic_core::constants::LIMITS_PROXY_MAX_BODY_BYTES {
                tracing::warn!(
                    "KIN-SEC-011: Blocked oversized P2P proxy request ({} bytes)",
                    req.body.len()
                );
                let _ = client_clone
                    .send_proxy_response(
                        channel,
                        ProxyResponse {
                            status: 413,
                            headers: Vec::new(),
                            body: bytes::Bytes::from_static(b"KIN-SEC-011: Payload Too Large"),
                        },
                    )
                    .await;
                return;
            }

            let url = format!("http://{}:{}{}", bind_ip_clone, local_port, safe_path);

            let method = match req.method.parse::<reqwest::Method>() {
                Ok(m) => m,
                Err(_) => {
                    tracing::warn!("KIN-SEC-012: Blocked invalid HTTP method: {}", req.method);
                    let _ = client_clone
                        .send_proxy_response(
                            channel,
                            ProxyResponse {
                                status: 400,
                                headers: Vec::new(),
                                body: bytes::Bytes::from_static(b"KIN-SEC-012: Bad Request: Invalid Method"),
                            },
                        )
                        .await;
                    return;
                }
            };

            let mut builder = reqwest_client.request(method, &url);

            for (k, v) in req.headers {
                if k.to_lowercase() == "host" {
                    continue;
                } // Never forward remote Host header
                builder = builder.header(k.as_ref(), v.as_ref());
            }
            builder = builder.header("Host", format!("{}:{}", bind_ip_clone, local_port));
            builder = builder.body(req.body);

            let proxy_res = match builder.send().await {
                Ok(res) => {
                    let mut status = res.status().as_u16();
                    let mut res_headers = Vec::new();
                    for (k, v) in res.headers() {
                        if let Ok(v_str) = v.to_str() {
                            res_headers.push((k.as_str().into(), v_str.into()));
                        }
                    }
                    use futures_util::StreamExt;
                    let mut body = Vec::new();
                    let mut stream = res.bytes_stream();
                    while let Some(chunk_res) = stream.next().await {
                        if let Ok(chunk) = chunk_res {
                            body.extend_from_slice(&chunk);
                            if body.len() > kinetic_core::constants::LIMITS_PROXY_MAX_BODY_BYTES {
                                tracing::warn!("KIN-SEC-013: Blocked oversized P2P backend response (>5MB)");
                                body.clear();
                                body.extend_from_slice(b"KIN-SEC-013: Payload Too Large");
                                status = 502; // Or 413
                                break;
                            }
                        }
                    }
                    ProxyResponse {
                        status,
                        headers: res_headers,
                        body: bytes::Bytes::from(body),
                    }
                }
                Err(e) => {
                    warn!("KIN-P2P-025: Failed to forward request to local web server: {}", e);
                    ProxyResponse {
                        status: 502,
                        headers: Vec::new(),
                        body: format!(
                            "KIN-P2P-025: Bad Gateway: Local web server not responding on port {}\nError: {}",
                            local_port, e
                        )
                        .into_bytes()
                        .into(),
                    }
                }
            };

            let _ = client_clone.send_proxy_response(channel, proxy_res).await;
        });
    }
}
