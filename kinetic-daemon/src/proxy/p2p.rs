use super::*;

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
                let _ = client_clone
                    .send_proxy_response(
                        channel,
                        ProxyResponse {
                            status: 400,
                            headers: Vec::new(),
                            body: bytes::Bytes::from_static(b"Bad Request: Invalid Path"),
                        },
                    )
                    .await;
                return;
            } else {
                &req.path
            };

            // Limit body size to 5MB to prevent OOM
            if req.body.len() > 5 * 1024 * 1024 {
                tracing::warn!(
                    "Blocked oversized P2P proxy request ({} bytes)",
                    req.body.len()
                );
                let _ = client_clone
                    .send_proxy_response(
                        channel,
                        ProxyResponse {
                            status: 413,
                            headers: Vec::new(),
                            body: bytes::Bytes::from_static(b"Payload Too Large"),
                        },
                    )
                    .await;
                return;
            }

            let url = format!("http://127.0.0.1:{}{}", local_port, safe_path);

            let method = match req.method.parse::<reqwest::Method>() {
                Ok(m) => m,
                Err(_) => {
                    tracing::warn!("Blocked invalid HTTP method: {}", req.method);
                    let _ = client_clone
                        .send_proxy_response(
                            channel,
                            ProxyResponse {
                                status: 400,
                                headers: Vec::new(),
                                body: bytes::Bytes::from_static(b"Bad Request: Invalid Method"),
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
            builder = builder.header("Host", format!("127.0.0.1:{}", local_port));
            builder = builder.body(req.body);

            let proxy_res = match builder.send().await {
                Ok(res) => {
                    let status = res.status().as_u16();
                    let mut res_headers = Vec::new();
                    for (k, v) in res.headers() {
                        if let Ok(v_str) = v.to_str() {
                            res_headers.push((k.as_str().into(), v_str.into()));
                        }
                    }
                    let body = res.bytes().await.unwrap_or_default().to_vec();
                    ProxyResponse {
                        status,
                        headers: res_headers,
                        body: bytes::Bytes::from(body),
                    }
                }
                Err(e) => {
                    warn!("Failed to forward request to local web server: {}", e);
                    ProxyResponse {
                        status: 502,
                        headers: Vec::new(),
                        body: format!(
                            "Bad Gateway: Local web server not responding on port {}\nError: {}",
                            local_port, e
                        )
                        .into_bytes().into(),
                    }
                }
            };

            let _ = client_clone.send_proxy_response(channel, proxy_res).await;
        });
    }
}
