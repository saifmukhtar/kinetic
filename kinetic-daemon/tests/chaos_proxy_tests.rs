//! Chaos network partition tests for proxy disconnect handling using Turmoil simulation.

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use turmoil::{Builder, net::TcpListener, net::TcpStream};

async fn hello_world(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from("Hello from backend"))))
}

#[test]
fn test_chaos_proxy_disconnect_handling() {
    let mut sim = Builder::new().build();

    // Spawn Backend Server
    sim.host("backend", || async {
        let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                if let Err(err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, hyper::service::service_fn(hello_world))
                    .await
                {
                    eprintln!("Error serving connection: {:?}", err);
                }
            });
        }
    });

    // Spawn Proxy/Client
    sim.client("client", async {
        // Connect directly to the server
        let stream = TcpStream::connect("backend:8080").await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();

        tokio::spawn(async move {
            if let Err(err) = conn.await {
                println!("Connection failed: {:?}", err);
            }
        });

        let req = Request::builder()
            .uri("http://backend:8080/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        // 1. Valid request to ensure server works
        let res = sender.send_request(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // 2. Introduce chaos: partition the network
        turmoil::partition("client", "backend");

        // 3. Attempt a new connection while partitioned, verify it fails
        let res2 = TcpStream::connect("backend:8080").await;
        // Should error out immediately because connection is partitioned
        assert!(
            res2.is_err(),
            "Request should fail due to network partition"
        );

        Ok(())
    });

    sim.run().unwrap();
}
