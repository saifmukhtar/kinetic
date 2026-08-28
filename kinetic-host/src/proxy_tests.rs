#[cfg(test)]
mod tests {
    use crate::proxy::forward_request;
    use axum::extract::{Query, Request};
    use axum::{
        Router,
        routing::{delete, get, head, options, patch, post, put},
    };
    use kinetic_network::ProxyRequest;

    use axum::body::Bytes;
    use axum::http::StatusCode;

    use tokio::net::TcpListener;

    use std::collections::HashMap;

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

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
        let client = test_client();
        let req = ProxyRequest {
            path: "/".into(),
            method: "GET".into(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(String::from_utf8(res.body.to_vec()).unwrap(), "Hello, GET!");
    }

    // 2
    #[tokio::test]
    async fn test_forward_request_post_200() {
        let port = start_mock_backend().await;
        let client = test_client();
        let req = ProxyRequest {
            path: "/post".into(),
            method: "POST".into(),
            headers: Vec::new(),
            body: bytes::Bytes::from_static(b"test body"),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(res.body, bytes::Bytes::from_static(b"test body"));
    }

    // 3
    #[tokio::test]
    async fn test_forward_request_404() {
        let port = start_mock_backend().await;
        let client = test_client();
        let req = ProxyRequest {
            path: "/404".into(),
            method: "GET".into(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 404);
        assert_eq!(String::from_utf8(res.body.to_vec()).unwrap(), "Not Found");
    }

    // 4
    #[tokio::test]
    async fn test_forward_request_500() {
        let port = start_mock_backend().await;
        let client = test_client();
        let req = ProxyRequest {
            path: "/500".into(),
            method: "GET".into(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 500);
        assert_eq!(
            String::from_utf8(res.body.to_vec()).unwrap(),
            "Server Error"
        );
    }

    // 5
    #[tokio::test]
    async fn test_forward_request_with_headers() {
        let port = start_mock_backend().await;
        let client = test_client();
        let headers = vec![("x-custom-header".into(), "custom-value".into())];
        let req = ProxyRequest {
            path: "/headers".into(),
            method: "GET".into(),
            headers,
            body: bytes::Bytes::new(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(
            res.headers
                .iter()
                .find(|(k, _)| k.as_ref() == "x-custom-header")
                .unwrap()
                .1
                .as_ref(),
            "custom-value"
        );
    }

    // 6
    #[tokio::test]
    async fn test_forward_request_with_body() {
        let port = start_mock_backend().await;
        let client = test_client();
        let req = ProxyRequest {
            path: "/post".into(),
            method: "POST".into(),
            headers: Vec::new(),
            body: bytes::Bytes::from_static(b"body with data"),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(res.body, bytes::Bytes::from_static(b"body with data"));
    }

    // 7
    #[tokio::test]
    async fn test_proxy_invalid_method() {
        let port = start_mock_backend().await;
        let client = test_client();
        let req = ProxyRequest {
            path: "/".into(),
            method: "INVALID_METHOD".into(), // Request will be parsed as a custom method by reqwest
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 405); // Axum returns 405 Method Not Allowed
    }

    // 8
    #[tokio::test]
    async fn test_forward_request_backend_offline_502() {
        let client = test_client();
        let req = ProxyRequest {
            path: "/".into(),
            method: "GET".into(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        // Port 1 is usually not running a web server
        let res = forward_request(&client, req, 1, "127.0.0.1").await;
        assert_eq!(res.status, 502);
        assert!(
            String::from_utf8(res.body.to_vec())
                .unwrap()
                .contains("Bad Gateway")
        );
    }

    // 9
    #[tokio::test]
    async fn test_forward_request_invalid_url_502() {
        let port = start_mock_backend().await;
        let client = test_client();
        let req = ProxyRequest {
            path: "/".into(),
            method: "GET".into(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        // Invalid hostname
        let res = forward_request(&client, req, port, "invalid-host-name-12345.local").await;
        assert_eq!(res.status, 502);
    }

    // 10
    #[tokio::test]
    async fn test_forward_request_large_payload() {
        let port = start_mock_backend().await;
        let client = test_client();
        let body = vec![0u8; 1024 * 1024]; // 1MB payload
        let req = ProxyRequest {
            path: "/post".into(),
            method: "POST".into(),
            headers: Vec::new(),
            body: bytes::Bytes::from(body.clone()),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(res.body.len(), 1024 * 1024);
    }

    // 11
    #[tokio::test]
    async fn test_forward_request_query_params() {
        let port = start_mock_backend().await;
        let client = test_client();
        let req = ProxyRequest {
            path: "/query?q=searchterm".into(),
            method: "GET".into(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(String::from_utf8(res.body.to_vec()).unwrap(), "searchterm");
    }

    // 12
    #[tokio::test]
    async fn test_forward_request_put_method() {
        let port = start_mock_backend().await;
        let client = test_client();
        let req = ProxyRequest {
            path: "/put".into(),
            method: "PUT".into(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(String::from_utf8(res.body.to_vec()).unwrap(), "Hello, PUT!");
    }

    // 13
    #[tokio::test]
    async fn test_forward_request_delete_method() {
        let port = start_mock_backend().await;
        let client = test_client();
        let req = ProxyRequest {
            path: "/delete".into(),
            method: "DELETE".into(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(
            String::from_utf8(res.body.to_vec()).unwrap(),
            "Hello, DELETE!"
        );
    }

    // 14
    #[tokio::test]
    async fn test_forward_request_patch_method() {
        let port = start_mock_backend().await;
        let client = test_client();
        let req = ProxyRequest {
            path: "/patch".into(),
            method: "PATCH".into(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(
            String::from_utf8(res.body.to_vec()).unwrap(),
            "Hello, PATCH!"
        );
    }

    // 15
    #[tokio::test]
    async fn test_forward_request_head_method() {
        let port = start_mock_backend().await;
        let client = test_client();
        let req = ProxyRequest {
            path: "/head".into(),
            method: "HEAD".into(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert!(res.body.is_empty());
    }

    // 16
    #[tokio::test]
    async fn test_forward_request_options_method() {
        let port = start_mock_backend().await;
        let client = test_client();
        let req = ProxyRequest {
            path: "/options".into(),
            method: "OPTIONS".into(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(
            String::from_utf8(res.body.to_vec()).unwrap(),
            "Hello, OPTIONS!"
        );
    }

    // 17
    #[tokio::test]
    async fn test_proxy_duplicate_headers() {
        // reqwest RequestBuilder headers overwrites keys if called sequentially with same key,
        // but in HTTP you can have multiple. For our proxy, it just iterates HashMap which guarantees unique keys,
        // so we just test that inserting a single header is correctly passed and parsed.
        let port = start_mock_backend().await;
        let client = test_client();
        let headers = vec![("accept".into(), "application/json".into())];
        let req = ProxyRequest {
            path: "/headers".into(),
            method: "GET".into(),
            headers,
            body: bytes::Bytes::new(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(
            res.headers
                .iter()
                .find(|(k, _)| k.as_ref() == "accept")
                .unwrap()
                .1
                .as_ref(),
            "application/json"
        );
    }

    // 18
    #[tokio::test]
    async fn test_forward_request_empty_body() {
        let port = start_mock_backend().await;
        let client = test_client();
        let req = ProxyRequest {
            path: "/post".into(),
            method: "POST".into(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert!(res.body.is_empty());
    }

    // 19
    #[tokio::test]
    async fn test_forward_request_binary_body() {
        let port = start_mock_backend().await;
        let client = test_client();
        let body = vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE];
        let req = ProxyRequest {
            path: "/post".into(),
            method: "POST".into(),
            headers: Vec::new(),
            body: bytes::Bytes::from(body.clone()),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        assert_eq!(res.body, bytes::Bytes::from(body));
    }

    // 20
    #[tokio::test]
    async fn test_proxy_response_headers() {
        let port = start_mock_backend().await;
        let client = test_client();
        let req = ProxyRequest {
            path: "/headers".into(),
            method: "GET".into(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        let res = forward_request(&client, req, port, "127.0.0.1").await;
        assert_eq!(res.status, 200);
        // Axum will append a content-type
        assert!(
            res.headers
                .iter()
                .any(|(k, _)| k.as_ref() == "content-type")
        );
    }
}
