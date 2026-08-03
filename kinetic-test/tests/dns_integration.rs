#[cfg(test)]
mod tests {
    use axum::{extract::Path, routing::get, Json, Router};
    use hickory_client::client::{AsyncClient, ClientHandle};
    use hickory_client::udp::UdpClientStream;
    use hickory_server::ServerFuture;
    use kinetic_core::types::{DnsRecord, DnsZone, Reveal, VdfProof};
    use kinetic_dns::KineticDnsHandler;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::str::FromStr;

    // A mock handler for the Daemon REST API
    async fn mock_resolve_name(
        Path(name): Path<String>,
    ) -> Result<Json<Reveal>, axum::http::StatusCode> {
        let name = name.trim_end_matches('.');
        if name == "testdns.kin" {
            let key_a = libp2p::identity::Keypair::generate_ed25519();
            let mut records = HashMap::new();
            records.insert(
                "@".to_string(),
                vec![DnsRecord::A("93.184.216.34".parse().unwrap())],
            );
            records.insert(
                "www".to_string(),
                vec![DnsRecord::A("93.184.216.35".parse().unwrap())],
            );

            let zone = DnsZone { records };
            let payload = serde_json::to_vec(&zone).unwrap();

            let mut reveal = Reveal {
                protocol_version: 1,
                name: "testdns.kin".to_string(),
                payload,
                salt: [0u8; 32],
                drand_kyn: 1000,
                drand_signature: "".to_string(),
                iterations: 100000,
                vdf_proof: VdfProof {
                    proof_bytes: vec![],
                },
                pubkey: key_a.public().encode_protobuf(),
                signature: vec![],
                previous_proof: None,
                miner_pubkey: None,
            };
            use ml_dsa::signature::Signer;
            use ml_dsa::{Generate, KeyExport, Keypair, SignatureEncoding};
            let keypair = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::generate();
            reveal.pubkey = keypair.verifying_key().to_bytes().to_vec();
            reveal.signature = keypair
                .sign(&reveal.signable_bytes(kinetic_core::constants::NETWORK_ID))
                .to_vec();
            Ok(Json(reveal))
        } else {
            Err(axum::http::StatusCode::NOT_FOUND)
        }
    }

    #[tokio::test]
    async fn test_dns_caching_and_coalescing() {
        // Start Axum mock server
        let app = Router::new().route("/api/resolve/{name}", get(mock_resolve_name));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_port = listener.local_addr().unwrap().port();
        let api_url = format!("http://127.0.0.1:{}", api_port);

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Start the DNS proxy server
        let handler = KineticDnsHandler::new(
            api_url,
            std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
            5354,
        );
        let mut server = ServerFuture::new(handler);
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_port = socket.local_addr().unwrap().port();
        server.register_socket(socket);

        // Setup hickory client
        let name_server: SocketAddr = format!("127.0.0.1:{}", dns_port).parse().unwrap();
        let stream = UdpClientStream::<tokio::net::UdpSocket>::new(name_server);
        let (mut client, bg) = AsyncClient::connect(stream).await.unwrap();
        tokio::spawn(bg);

        // 1. Query an A record (should hit DHT/Mock API)
        let name = hickory_proto::rr::Name::from_str("testdns.kin.").unwrap();
        let response = client
            .query(
                name.clone(),
                hickory_proto::rr::DNSClass::IN,
                hickory_proto::rr::RecordType::A,
            )
            .await
            .unwrap();

        assert_eq!(
            response.response_code(),
            hickory_proto::op::ResponseCode::NoError
        );
        let answers = response.answers();
        assert_eq!(answers.len(), 1);

        if let Some(hickory_proto::rr::RData::A(ipv4)) = answers[0].data() {
            assert_eq!(ipv4.to_string(), "93.184.216.34");
        } else {
            panic!("Expected A record");
        }

        // 2. Query www subdomain (should hit CACHE instantly)
        let www_name = hickory_proto::rr::Name::from_str("www.testdns.kin.").unwrap();
        let start = std::time::Instant::now();
        let response_www = client
            .query(
                www_name,
                hickory_proto::rr::DNSClass::IN,
                hickory_proto::rr::RecordType::A,
            )
            .await
            .unwrap();
        let elapsed = start.elapsed();

        assert_eq!(
            response_www.response_code(),
            hickory_proto::op::ResponseCode::NoError
        );
        assert!(
            elapsed.as_millis() < 50,
            "Cache lookup should be near-instant"
        );

        // 3. Query NXDOMAIN for negative caching
        let bad_name = hickory_proto::rr::Name::from_str("doesntexist.kin.").unwrap();
        let response_bad = client
            .query(
                bad_name.clone(),
                hickory_proto::rr::DNSClass::IN,
                hickory_proto::rr::RecordType::A,
            )
            .await
            .unwrap();
        assert_eq!(
            response_bad.response_code(),
            hickory_proto::op::ResponseCode::NXDomain
        );

        // Query again to ensure NXDomain is cached
        let start_bad = std::time::Instant::now();
        let response_bad2 = client
            .query(
                bad_name,
                hickory_proto::rr::DNSClass::IN,
                hickory_proto::rr::RecordType::A,
            )
            .await
            .unwrap();
        let elapsed_bad = start_bad.elapsed();

        assert_eq!(
            response_bad2.response_code(),
            hickory_proto::op::ResponseCode::NXDomain
        );
        assert!(
            elapsed_bad.as_millis() < 50,
            "Negative Cache lookup should be near-instant"
        );
    }

    // A mock handler that intentionally hangs
    async fn mock_resolve_timeout(
        Path(_name): Path<String>,
    ) -> Result<Json<Reveal>, axum::http::StatusCode> {
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
        Err(axum::http::StatusCode::NOT_FOUND)
    }

    #[tokio::test]
    async fn test_dns_timeout() {
        // Start Axum mock server with hanging handler
        let app = Router::new().route("/api/resolve/{name}", get(mock_resolve_timeout));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_port = listener.local_addr().unwrap().port();
        let api_url = format!("http://127.0.0.1:{}", api_port);

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Start the DNS proxy server
        let handler = KineticDnsHandler::new(
            api_url,
            std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
            5354,
        );
        let mut server = ServerFuture::new(handler);
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_port = socket.local_addr().unwrap().port();
        server.register_socket(socket);

        // Setup hickory client with a 7 second timeout (greater than the reqwest 5s timeout)
        let name_server: SocketAddr = format!("127.0.0.1:{}", dns_port).parse().unwrap();
        let stream = UdpClientStream::<tokio::net::UdpSocket>::with_timeout(
            name_server,
            std::time::Duration::from_secs(7),
        );
        let (mut client, bg) = AsyncClient::connect(stream).await.unwrap();
        tokio::spawn(bg);

        // Query an A record
        let name = hickory_proto::rr::Name::from_str("timeout.kin.").unwrap();
        let response = client
            .query(
                name.clone(),
                hickory_proto::rr::DNSClass::IN,
                hickory_proto::rr::RecordType::A,
            )
            .await
            .unwrap();

        assert_eq!(
            response.response_code(),
            hickory_proto::op::ResponseCode::ServFail
        );
    }
}
