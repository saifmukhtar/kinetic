use kinetic_network::{NetworkClient, ProxyRequest, ProxyResponse};
use std::collections::HashMap;
use tracing::{info, warn};

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
            let url = format!("http://127.0.0.1:{}{}", local_port, req.path);

            let mut builder =
                reqwest_client.request(req.method.parse().unwrap_or(reqwest::Method::GET), &url);

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
