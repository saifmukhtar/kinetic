use super::*;
use hyper::{Request, Response};

/// Rewrites and forwards the proxy request to a local IPFS gateway.
pub async fn forward_to_ipfs<B>(
    req: Request<B>,
    config: Arc<kinetic_core::config::KineticConfig>,
    cid: &str,
) -> Result<Response<axum::body::Body>, ProxyError>
where
    B: hyper::body::Body + Send + Unpin + 'static,
    B::Data: Send + AsRef<[u8]>,
    B::Error: std::fmt::Debug,
{
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .trim_start_matches('/')
        .to_string();

    let method = req.method().clone();

    let mut req_headers = hyper::HeaderMap::new();
    for (name, value) in req.headers() {
        if name != hyper::header::HOST {
            req_headers.insert(name.clone(), value.clone());
        }
    }

    use http_body_util::BodyExt;
    let mut body_bytes = Vec::new();
    let mut body_stream = req.into_body();
    while let Some(chunk_res) = body_stream.frame().await {
        if let Ok(frame) = chunk_res
            && let Ok(data) = frame.into_data()
        {
            body_bytes.extend_from_slice(data.as_ref());
            if body_bytes.len() > kinetic_core::constants::LIMITS_PROXY_MAX_BODY_BYTES {
                let err = kinetic_core::error::SecurityError::PayloadTooLarge;
                tracing::warn!(
                    error_code = err.code(),
                    "Blocked oversized IPFS proxy request body"
                );
                return Err(ProxyError::InvalidPayload(
                    "Blocked oversized IPFS proxy request body".to_string(),
                ));
            }
        }
    }

    let gateways: Vec<&str> = config
        .daemon
        .ipfs_gateway
        .split(',')
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .collect();

    if gateways.is_empty() {
        return Err(ProxyError::Other("No IPFS gateways configured".to_string()));
    }

    let mut last_error = None;

    for gateway in gateways {
        let ipfs_url = if path.is_empty() {
            format!("{}/{}", gateway, cid)
        } else {
            format!("{}/{}/{}", gateway, cid, path)
        };

        let err = kinetic_core::error::GatewayError::ProxyingToGateway(ipfs_url.to_string());
        tracing::info!(error_code = err.code(), "{}", err);

        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let mut out_req = client.request(method.clone(), &ipfs_url);
        out_req = out_req.headers(req_headers.clone());
        out_req = out_req.body(body_bytes.clone());

        match out_req.send().await {
            Ok(backend_resp) => {
                let status = backend_resp.status();
                if status.is_server_error() || status == reqwest::StatusCode::NOT_FOUND {
                    let err = kinetic_core::error::GatewayError::GatewayFailedWithStatus(
                        gateway.to_string(),
                        status.to_string(),
                    );
                    tracing::warn!(error_code = err.code(), "{}. Trying next...", err);
                    last_error = Some(format!("Gateway returned {}", status));
                    continue;
                }

                let mut resp_builder = Response::builder().status(status);

                for (name, value) in backend_resp.headers() {
                    if name.as_str().to_lowercase() == "strict-transport-security" {
                        continue;
                    }
                    resp_builder = resp_builder.header(name, value);
                }

                let body_stream = backend_resp.bytes_stream();
                let body = axum::body::Body::from_stream(body_stream);
                return Ok(resp_builder.body(body)?);
            }
            Err(e) => {
                let err = kinetic_core::error::GatewayError::GatewayUnreachable(
                    gateway.to_string(),
                    e.to_string(),
                );
                tracing::warn!(error_code = err.code(), "{}. Trying next...", err);
                last_error = Some(e.to_string());
                continue;
            }
        }
    }

    let err = kinetic_core::error::GatewayError::AllGatewaysFailed(cid.to_string());
    tracing::error!(error_code = err.code(), "{}", err);
    Err(ProxyError::PeerUnreachable(format!(
        "{}: {}. Last error: {}",
        err.code(),
        err,
        last_error.unwrap_or_else(|| "None".to_string())
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{Expectation, Server, matchers::*, responders::*};
    use hyper::Request;
    use kinetic_core::config::KineticConfig;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_ipfs_gateway_fallback() {
        let server_private = Server::run();
        let server_public = Server::run();

        // Private gateway fails with 404 Not Found
        server_private.expect(
            Expectation::matching(request::method_path("GET", "/ipfs/QmTestCID123/img.png"))
                .respond_with(status_code(404)),
        );

        // Public gateway succeeds with 200 OK
        server_public.expect(
            Expectation::matching(request::method_path("GET", "/ipfs/QmTestCID123/img.png"))
                .respond_with(status_code(200).body("success_image_bytes")),
        );

        let mut config = KineticConfig::default();
        config.daemon.ipfs_gateway = format!(
            "{}, {}",
            server_private.url_str("/ipfs/"),
            server_public.url_str("/ipfs/")
        );

        // Use http_body_util::Full to mock a generic Body in tests
        let req = Request::builder()
            .method("GET")
            .uri("http://site.kin/img.png")
            .body(http_body_util::Full::new(bytes::Bytes::from("")))
            .unwrap();

        let resp = forward_to_ipfs(req, Arc::new(config), "QmTestCID123")
            .await
            .expect("Fallback loop should succeed");
        assert_eq!(resp.status(), 200);

        use http_body_util::BodyExt;
        let mut body_bytes = Vec::new();
        let mut body_stream = resp.into_body();
        while let Some(chunk_res) = body_stream.frame().await {
            if let Ok(frame) = chunk_res
                && let Ok(data) = frame.into_data() {
                    body_bytes.extend_from_slice(&data);
                }
        }

        assert_eq!(body_bytes, b"success_image_bytes");
    }
}
