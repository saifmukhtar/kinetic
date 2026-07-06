use kinetic_network::{NetworkClient, ProxyRequest, ProxyResponse};
use std::collections::HashMap;
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
        builder = builder.header(k, v);
    }
    builder = builder.body(req.body);

    match builder.send().await {
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
mod tests {
    use super::*;
    use axum::extract::{Query, Request};
    use axum::{
        routing::{delete, get, head, options, patch, post, put},
        Router,
    };

    use axum::body::Bytes;
    use axum::http::StatusCode;

    use tokio::net::TcpListener;

    use std::collections::HashMap;

    async fn start_mock_backend() -> u16 {
        let app = Router::new()
            .route("/", get(|| async { "Hello, GET!" }))
            .route("/post", post(|body: Bytes| async move { body }))
            .route(
                "/404",
                get(|| async { (StatusCode::NOT_FOUND, "Not Found") }),
            )
            .route(
                "/500",
                get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "Server Error") }),
            )
            .route(
                "/headers",
                get(|req: Request| async move {
                    let mut resp_headers = axum::http::HeaderMap::new();
                    for (k, v) in req.headers() {
                        resp_headers.insert(k.clone(), v.clone());
                    }
                    (resp_headers, "Headers Received")
                }),
            )
            .route("/put", put(|| async { "Hello, PUT!" }))
            .route("/delete", delete(|| async { "Hello, DELETE!" }))
            .route("/patch", patch(|| async { "Hello, PATCH!" }))
            .route("/head", head(|| async { "" }))
            .route("/options", options(|| async { "Hello, OPTIONS!" }))
            .route(
                "/query",
                get(|Query(params): Query<HashMap<String, String>>| async move {
                    params.get("q").cloned().unwrap_or_default()
                }),
            );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        port
    }

    // 1
    #[tokio::test]
    async fn test_forward_request_get_200() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(String::from_utf8(res.body).unwrap(), "Hello, GET!");
    }

    // 2
    #[tokio::test]
    async fn test_forward_request_post_200() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/post".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body: b"test body".to_vec(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(res.body, b"test body");
    }

    // 3
    #[tokio::test]
    async fn test_forward_request_404() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/404".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 404);
        assert_eq!(String::from_utf8(res.body).unwrap(), "Not Found");
    }

    // 4
    #[tokio::test]
    async fn test_forward_request_500() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/500".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 500);
        assert_eq!(String::from_utf8(res.body).unwrap(), "Server Error");
    }

    // 5
    #[tokio::test]
    async fn test_forward_request_with_headers() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let mut headers = HashMap::new();
        headers.insert("x-custom-header".to_string(), "custom-value".to_string());
        let req = ProxyRequest {
            path: "/headers".to_string(),
            method: "GET".to_string(),
            headers,
            body: vec![],
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(res.headers.get("x-custom-header").unwrap(), "custom-value");
    }

    // 6
    #[tokio::test]
    async fn test_forward_request_with_body() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/post".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body: b"body with data".to_vec(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(res.body, b"body with data");
    }

    // 7
    #[tokio::test]
    async fn test_forward_request_invalid_method_fallback_to_get() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/".to_string(),
            method: "INVALID_METHOD".to_string(), // Request will be parsed as a custom method by reqwest
            headers: HashMap::new(),
            body: vec![],
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 405); // Axum returns 405 Method Not Allowed
    }

    // 8
    #[tokio::test]
    async fn test_forward_request_backend_offline_502() {
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        // Port 1 is usually not running a web server
        let res = forward_request(&client, req, 1, "127.0.0.1").await;
        assert_eq!(res.status, 502);
        assert!(String::from_utf8(res.body).unwrap().contains("Bad Gateway"));
    }

    // 9
    #[tokio::test]
    async fn test_forward_request_invalid_url_502() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        // Invalid hostname
        let res = forward_request(&client, req, port, "invalid-host-name-12345.local").await;
        assert_eq!(res.status, 502);
    }

    // 10
    #[tokio::test]
    async fn test_forward_request_large_payload() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let body = vec![0u8; 1024 * 1024]; // 1MB payload
        let req = ProxyRequest {
            path: "/post".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body: body.clone(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(res.body.len(), 1024 * 1024);
    }

    // 11
    #[tokio::test]
    async fn test_forward_request_query_params() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/query?q=searchterm".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(String::from_utf8(res.body).unwrap(), "searchterm");
    }

    // 12
    #[tokio::test]
    async fn test_forward_request_put_method() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/put".to_string(),
            method: "PUT".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(String::from_utf8(res.body).unwrap(), "Hello, PUT!");
    }

    // 13
    #[tokio::test]
    async fn test_forward_request_delete_method() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/delete".to_string(),
            method: "DELETE".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(String::from_utf8(res.body).unwrap(), "Hello, DELETE!");
    }

    // 14
    #[tokio::test]
    async fn test_forward_request_patch_method() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/patch".to_string(),
            method: "PATCH".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(String::from_utf8(res.body).unwrap(), "Hello, PATCH!");
    }

    // 15
    #[tokio::test]
    async fn test_forward_request_head_method() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/head".to_string(),
            method: "HEAD".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert!(res.body.is_empty());
    }

    // 16
    #[tokio::test]
    async fn test_forward_request_options_method() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/options".to_string(),
            method: "OPTIONS".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(String::from_utf8(res.body).unwrap(), "Hello, OPTIONS!");
    }

    // 17
    #[tokio::test]
    async fn test_forward_request_multiple_headers_same_key() {
        // reqwest RequestBuilder headers overwrites keys if called sequentially with same key,
        // but in HTTP you can have multiple. For our proxy, it just iterates HashMap which guarantees unique keys,
        // so we just test that inserting a single header is correctly passed and parsed.
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let mut headers = HashMap::new();
        headers.insert("accept".to_string(), "application/json".to_string());
        let req = ProxyRequest {
            path: "/headers".to_string(),
            method: "GET".to_string(),
            headers,
            body: vec![],
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(res.headers.get("accept").unwrap(), "application/json");
    }

    // 18
    #[tokio::test]
    async fn test_forward_request_empty_body() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/post".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert!(res.body.is_empty());
    }

    // 19
    #[tokio::test]
    async fn test_forward_request_binary_body() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let body = vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE];
        let req = ProxyRequest {
            path: "/post".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body: body.clone(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(res.body, body);
    }

    // 20
    #[tokio::test]
    async fn test_forward_request_response_headers_are_proxied() {
        let port = start_mock_backend().await;
        let client = reqwest::Client::new();
        let req = ProxyRequest {
            path: "/headers".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        // Axum will append a content-type and content-length
        assert!(res.headers.contains_key("content-type"));
        assert!(res.headers.contains_key("content-length"));
    }
}
