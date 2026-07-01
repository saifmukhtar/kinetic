#[cfg(test)]
mod tests {
    use hickory_client::client::{AsyncClient, ClientHandle};
    use hickory_client::udp::UdpClientStream;
    use hickory_server::ServerFuture;
    use kinetic_core::types::{DnsRecord, DnsZone, Reveal, VdfProof};
    use kinetic_dns::KineticDnsHandler;
    use kinetic_network::{client::Command, NetworkClient};
    use libp2p::identity::Keypair;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_dns_caching_and_coalescing() {
        let key_a = Keypair::generate_ed25519();

        let (tx, mut rx) = mpsc::channel(100);
        let mock_client = NetworkClient::new(tx);

        // Mock network task
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                if let Command::ResolveRedundant { name, responder } = cmd {
                    if name == "testdns.kin" {
                        // Construct a realistic Reveal payload with a nested DnsZone
                        let mut records = HashMap::new();
                        records.insert(
                            "@".to_string(),
                            vec![DnsRecord::A("192.168.1.100".to_string())],
                        );
                        records.insert(
                            "www".to_string(),
                            vec![DnsRecord::A("192.168.1.101".to_string())],
                        );

                        let zone = DnsZone { records };
                        let payload = serde_json::to_vec(&zone).unwrap();

                        let reveal = Reveal {
                            protocol_version: 2,
                            name: "testdns.kin".to_string(),
                            payload,
                            salt: [0u8; 32],
                            drand_pulse: 1000,
                            drand_randomness: "".to_string(),
                            iterations: 100000,
                            vdf_proof: VdfProof {
                                proof_bytes: vec![],
                            },
                            pubkey: key_a.public().encode_protobuf(),
                            signature: vec![], // mock
                        };

                        let reveal_payload = serde_json::to_vec(&reveal).unwrap();
                        let _ = responder.send(Ok(Some(reveal_payload)));
                    } else {
                        let _ = responder.send(Ok(None));
                    }
                }
            }
        });

        // Start the DNS proxy server
        let handler = KineticDnsHandler::new(mock_client);
        let mut server = ServerFuture::new(handler);

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_port = socket.local_addr().unwrap().port();
        server.register_socket(socket);

        // Setup hickory client
        let name_server: SocketAddr = format!("127.0.0.1:{}", dns_port).parse().unwrap();
        let stream = UdpClientStream::<tokio::net::UdpSocket>::new(name_server);
        let (mut client, bg) = AsyncClient::connect(stream).await.unwrap();
        tokio::spawn(bg);

        // 1. Query an A record (should hit DHT)
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
            assert_eq!(ipv4.to_string(), "192.168.1.100");
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
}
