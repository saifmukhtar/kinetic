use axum::{routing::get, Router};
use libp2p::PeerId;

pub fn build_router(local_peer_id: PeerId) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/peer_id",
            get(move || async move { local_peer_id.to_string() }),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use libp2p::identity::Keypair;
    use tower::ServiceExt; // for `oneshot`

    #[tokio::test]
    async fn test_health_endpoint() {
        let key = Keypair::generate_ed25519();
        let peer_id = key.public().to_peer_id();

        let app = build_router(peer_id);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"OK");
    }

    #[tokio::test]
    async fn test_peer_id_endpoint() {
        let key = Keypair::generate_ed25519();
        let peer_id = key.public().to_peer_id();

        let app = build_router(peer_id);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/peer_id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let response_peer_id = String::from_utf8(body.to_vec()).unwrap();

        assert_eq!(response_peer_id, peer_id.to_string());
    }

    #[tokio::test]
    async fn test_health_endpoint_post_method_rejected() {
        let key = Keypair::generate_ed25519();
        let app = build_router(key.public().to_peer_id());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // axum returns 405 Method Not Allowed if route exists but method doesn't match
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_peer_id_endpoint_put_method_rejected() {
        let key = Keypair::generate_ed25519();
        let app = build_router(key.public().to_peer_id());

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/peer_id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_unknown_route_returns_404() {
        let key = Keypair::generate_ed25519();
        let app = build_router(key.public().to_peer_id());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/does_not_exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_health_endpoint_ignores_query_params() {
        let key = Keypair::generate_ed25519();
        let app = build_router(key.public().to_peer_id());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health?foo=bar")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
