use kinetic_network::{NetworkClient, ProxyRequest, ProxyResponse};

use tracing::{info, warn};

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
        builder = builder.header(k.as_ref(), v.as_ref());
    }
    builder = builder.body(req.body);

    match builder.send().await {
        Ok(res) => {
            let status = res.status().as_u16();
            let mut res_headers = Vec::new();
            for (k, v) in res.headers() {
                if let Ok(v_str) = v.to_str() {
                    res_headers.push((k.as_str().into(), v_str.into()));
                }
            }
            let body = res.bytes().await.unwrap_or_default();
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

pub async fn handle_incoming_proxy_requests(
    client: NetworkClient,
    mut rx: tokio::sync::mpsc::Receiver<(
        ProxyRequest,
        libp2p::request_response::ResponseChannel<ProxyResponse>,
    )>,
    local_port: u16,
    backend_host: String,
) {
    let reqwest_client = reqwest::Client::new();
    info!(
        "Listening for incoming P2P Proxy requests, forwarding to {}:{}",
        backend_host, local_port
    );

    while let Some((req, channel)) = rx.recv().await {
        let reqwest_client = reqwest_client.clone();
        let client_clone = client.clone();
        let backend_host_clone = backend_host.clone();

        tokio::spawn(async move {
            let proxy_res =
                forward_request(&reqwest_client, req, local_port, &backend_host_clone).await;
            let _ = client_clone.send_proxy_response(channel, proxy_res).await;
        });
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use kinetic_network::ProxyRequest;

    proptest! {
        #[test]
        fn proxy_handles_chaotic_requests_gracefully(
            method in "[a-zA-Z]{1,10}",
            path in "/[a-zA-Z0-9%_=+-]*",
            body in prop::collection::vec(any::<u8>(), 0..50)
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let client = reqwest::Client::new();
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
