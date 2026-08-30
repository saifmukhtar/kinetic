use kinetic_network::{NetworkClient, ProxyRequest, ProxyResponse};

use tracing::{info, warn};

/// Forwards a P2P proxy request to the local web server.
///
/// Takes a `ProxyRequest` received from the DHT network and translates it into
/// a standard HTTP request to the configured local backend (e.g. `localhost:8080`).
/// Returns a `ProxyResponse` which will be routed back to the requester.
pub async fn forward_request(
    reqwest_client: &reqwest::Client,
    req: ProxyRequest,
    local_port: u16,
    backend_host: &str,
) -> ProxyResponse {
    let url = format!("http://{}:{}{}", backend_host, local_port, req.path);

    let mut builder =
        reqwest_client.request(req.method.parse().unwrap_or(reqwest::Method::GET), &url);

    for (k, v) in req.headers {
        if k.to_lowercase() == "host" {
            continue; // Never forward remote Host header to prevent Virtual Host SSRF
        }
        builder = builder.header(k.as_ref(), v.as_ref());
    }

    builder = builder.header("Host", format!("{}:{}", backend_host, local_port));
    builder = builder.body(req.body);

    match builder.send().await {
        Ok(res) => {
            let mut status = res.status().as_u16();
            let mut res_headers = Vec::new();
            for (k, v) in res.headers() {
                let header_name = k.as_str().to_lowercase();
                if header_name == "content-encoding"
                    || header_name == "transfer-encoding"
                    || header_name == "content-length"
                    || header_name == "connection"
                    || header_name == "keep-alive"
                    || header_name == "upgrade"
                {
                    continue;
                }
                
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
                        warn!("KIN-SEC-013: Blocked oversized backend response from local web server");
                        body.clear();
                        body.extend_from_slice(b"Payload Too Large");
                        status = 502;
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
            warn!("KIN-P2P-025: Failed to forward P2P request to local backend web server: {}", e);
            ProxyResponse {
                status: 502,
                headers: Vec::new(),
                body: format!(
                    "Bad Gateway: Local web server not responding on port {}\nError: {}",
                    local_port, e
                )
                .into_bytes()
                .into(),
            }
        }
    }
}

/// Background task to handle incoming P2P proxy requests continuously.
///
/// Listens on the provided `rx` channel for incoming requests from the network
/// client, processes them concurrently by forwarding them to the local backend,
/// and sends the responses back over the P2P channel.
pub async fn handle_incoming_proxy_requests(
    client: NetworkClient,
    mut rx: tokio::sync::mpsc::Receiver<(
        ProxyRequest,
        libp2p::request_response::ResponseChannel<ProxyResponse>,
    )>,
) {
    let reqwest_client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap_or_default();
    info!("Listening for incoming P2P Proxy requests, forwarding based on dynamic config");

    let concurrency_limit = std::sync::Arc::new(tokio::sync::Semaphore::new(100));

    while let Some((req, channel)) = rx.recv().await {
        let reqwest_client = reqwest_client.clone();
        let client_clone = client.clone();

        let config_path = kinetic_core::config::get_base_dir().join("host_config.json");
        let host_config = crate::config::HostConfig::load_or_default(&config_path);
        let backend_host_clone = host_config.backend_host;
        let local_port = host_config.backend_port;

        let permit = concurrency_limit.clone().acquire_owned().await.unwrap();

        tokio::spawn(async move {
            let _permit = permit;
            let decoded_path = percent_encoding::percent_decode_str(&req.path)
                .decode_utf8()
                .unwrap_or(std::borrow::Cow::Owned(req.path.to_string()));

            if decoded_path.contains("..") || !decoded_path.starts_with('/') {
                warn!("KIN-SEC-010: Security exception: Blocked malicious P2P proxy path traversal attempt: {}", req.path);
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
            }

            if req.body.len() > kinetic_core::constants::LIMITS_PROXY_MAX_BODY_BYTES {
                warn!(
                    "KIN-SEC-011: Blocked oversized incoming P2P proxy request payload ({} bytes)",
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

            let proxy_res =
                forward_request(&reqwest_client, req, local_port, &backend_host_clone).await;
            let _ = client_clone.send_proxy_response(channel, proxy_res).await;
        });
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use kinetic_network::ProxyRequest;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_proxy_chaotic_requests(
            method in "[a-zA-Z]{1,10}",
            path in "/[a-zA-Z0-9%_=+-]*",
            body in prop::collection::vec(any::<u8>(), 0..50)
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let req = ProxyRequest {
                method: method.into(),
                path: path.into(),
                headers: vec![],
                body: body.into(),
            };

            let res = rt.block_on(forward_request(&client, req, 65534, "127.0.0.1"));

            // Should never panic, and since the backend port is dead, it MUST return a 502 Bad Gateway
            prop_assert_eq!(res.status, 502);
            prop_assert!(String::from_utf8_lossy(&res.body).contains("Bad Gateway"));
        }
    }
}
