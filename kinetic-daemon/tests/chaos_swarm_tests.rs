use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use tokio::task::JoinSet;
use turmoil::{net::TcpListener, net::TcpStream, Builder};

async fn hello_world(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from("Daemon pulse active"))))
}

#[test]
fn test_chaos_swarm_nodes() {
    let mut sim = Builder::new()
        .simulation_duration(std::time::Duration::from_secs(15))
        .build();
    let num_daemons = 100;

    // 1. Spawn 500 Backend Daemons
    for i in 0..num_daemons {
        let hostname = format!("daemon-{}", i);
        sim.host(hostname, || async {
            let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let io = TokioIo::new(stream);
                    tokio::spawn(async move {
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, hyper::service::service_fn(hello_world))
                            .await;
                    });
                }
            }
        });
    }

    // 2. Spawn the load-testing Client
    sim.client("client", async move {
        let mut join_set = JoinSet::new();

        // PHASE 1: Verify all 500 nodes are reachable and healthy
        for i in 0..num_daemons {
            join_set.spawn(async move {
                let hostname = format!("daemon-{}:8080", i);
                let stream_res = TcpStream::connect(&hostname).await;
                if stream_res.is_err() {
                    return false;
                }

                let stream = stream_res.unwrap();
                let io = TokioIo::new(stream);

                let handshake = hyper::client::conn::http1::handshake(io).await;
                if handshake.is_err() {
                    return false;
                }

                let (mut sender, conn) = handshake.unwrap();
                tokio::spawn(async move {
                    let _ = conn.await;
                });

                let req = Request::builder()
                    .uri(format!("http://{}/", hostname))
                    .body(Full::new(Bytes::new()))
                    .unwrap();

                let res = sender.send_request(req).await;
                res.is_ok() && res.unwrap().status() == StatusCode::OK
            });
        }

        // Await all initial connections
        let mut successful = 0;
        while let Some(res) = join_set.join_next().await {
            if res.unwrap() {
                successful += 1;
            }
        }
        assert_eq!(
            successful, num_daemons,
            "All {} daemons should be online",
            num_daemons
        );
        println!(
            "✅ PHASE 1: Successfully pinged all {} daemons.",
            num_daemons
        );

        // PHASE 2: CHAOS! Partition half of the network (250 nodes)
        println!("💥 PHASE 2: Injecting chaos! Severing network for 250 daemons...");
        for i in 0..(num_daemons / 2) {
            let target = format!("daemon-{}", i);
            turmoil::partition("client", target);
        }

        // PHASE 3: Verify graceful degradation (250 hit, 250 fail deterministically)
        let mut chaos_set = JoinSet::new();
        for i in 0..num_daemons {
            chaos_set.spawn(async move {
                let hostname = format!("daemon-{}:8080", i);
                match TcpStream::connect(&hostname).await {
                    Ok(stream) => {
                        let io = TokioIo::new(stream);
                        if let Ok((mut sender, conn)) =
                            hyper::client::conn::http1::handshake(io).await
                        {
                            tokio::spawn(async move {
                                let _ = conn.await;
                            });
                            let req = Request::builder()
                                .uri(format!("http://{}/", hostname))
                                .body(Full::new(Bytes::new()))
                                .unwrap();

                            sender.send_request(req).await.is_ok()
                        } else {
                            false
                        }
                    }
                    Err(_) => false,
                }
            });
        }

        let mut alive_count = 0;
        let mut dead_count = 0;

        while let Some(res) = chaos_set.join_next().await {
            if res.unwrap() {
                alive_count += 1;
            } else {
                dead_count += 1;
            }
        }

        println!(
            "✅ PHASE 3: Chaos resolved! {} survived, {} safely failed.",
            alive_count, dead_count
        );
        assert_eq!(
            alive_count,
            num_daemons / 2,
            "Exactly half the nodes should survive"
        );
        assert_eq!(
            dead_count,
            num_daemons / 2,
            "Exactly half the nodes should fail gracefully"
        );

        Ok(())
    });

    sim.run().unwrap();
}
