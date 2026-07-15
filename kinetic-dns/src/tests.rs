use crate::KineticDnsHandler;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{routing::get, Router};
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RecordType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Clone)]
struct MockResponseHandler {
    pub responses: Arc<Mutex<Vec<Message>>>,
}

#[async_trait::async_trait]
impl ResponseHandler for MockResponseHandler {
    async fn send_response<'a>(
        &mut self,
        response: hickory_server::authority::MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
        >,
    ) -> std::io::Result<ResponseInfo> {
        // We construct a mock Message from the response parts since MessageResponse is opaque
        let mut msg = Message::new();
        msg.set_header(*response.header());
        self.responses.lock().await.push(msg);

        Ok(ResponseInfo::from(*response.header()))
    }
}

async fn start_mock_daemon() -> String {
    let app = Router::new().route(
        "/api/resolve/:domain",
        get(|Path(domain): Path<String>| async move {
            match domain.as_str() {
                "test1.kin" => {
                    let mut zone = kinetic_core::types::DnsZone {
                        records: std::collections::HashMap::new(),
                    };
                    zone.records.insert(
                        "@".to_string(),
                        vec![kinetic_core::types::DnsRecord::A(
                            "1.2.3.4".parse().unwrap(),
                        )],
                    );
                    let payload = serde_json::to_vec(&zone).unwrap();
                    let reveal = kinetic_core::types::Reveal {
                        protocol_version: 1,
                        name: "test1.kin".to_string(),
                        payload,
                        salt: [0u8; 32],
                        drand_pulse: 0,
                        drand_randomness: "".to_string(),
                        vdf_proof: kinetic_core::types::VdfProof {
                            proof_bytes: vec![],
                        },
                        iterations: 1,
                        pubkey: vec![],
                        signature: vec![],
                        miner_pubkey: None,
                        previous_proof: None,
                    };
                    (StatusCode::OK, serde_json::to_vec(&reveal).unwrap()).into_response()
                }
                "invalid-payload.kin" => (StatusCode::OK, vec![0, 1, 2, 3]).into_response(),
                "invalid-zone.kin" => {
                    let reveal = kinetic_core::types::Reveal {
                        protocol_version: 1,
                        name: "invalid-zone.kin".to_string(),
                        payload: vec![1, 2, 3, 4], // Invalid JSON for DnsZone
                        salt: [0u8; 32],
                        drand_pulse: 0,
                        drand_randomness: "".to_string(),
                        vdf_proof: kinetic_core::types::VdfProof {
                            proof_bytes: vec![],
                        },
                        iterations: 1,
                        pubkey: vec![],
                        signature: vec![],
                        miner_pubkey: None,
                        previous_proof: None,
                    };
                    (StatusCode::OK, serde_json::to_vec(&reveal).unwrap()).into_response()
                }
                "500.kin" => (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response(),
                _ => (StatusCode::NOT_FOUND, "Not found").into_response(),
            }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://127.0.0.1:{}", port)
}

async fn build_request(name: &str, rtype: RecordType) -> Request {
    let mut msg = Message::new();
    msg.add_query(hickory_proto::op::Query::query(
        Name::from_str(name).unwrap(),
        rtype,
    ));

    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    let bytes = msg.to_bytes().unwrap();
    let msg_request = hickory_server::authority::MessageRequest::from_bytes(&bytes).unwrap();

    let src = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 12345);
    Request::new(msg_request, src, hickory_server::server::Protocol::Udp)
}

// 1. Test resolving standard domain passes to cloudflare
#[tokio::test]
async fn test_resolve_standard_domain() {
    let api_url = start_mock_daemon().await;
    let handler = KineticDnsHandler::new(api_url);

    let req = build_request("google.com.", RecordType::A).await;
    let responses = Arc::new(Mutex::new(Vec::new()));
    let responder = MockResponseHandler {
        responses: responses.clone(),
    };

    let info = handler.handle_request(&req, responder).await;
    assert_eq!(
        info.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );
}

// 2. Test successful resolve of .kin domain
#[tokio::test]
async fn test_resolve_kin_success() {
    let api_url = start_mock_daemon().await;
    let handler = KineticDnsHandler::new(api_url);

    let req = build_request("test1.kin.", RecordType::A).await;
    let responses = Arc::new(Mutex::new(Vec::new()));
    let responder = MockResponseHandler {
        responses: responses.clone(),
    };

    let info = handler.handle_request(&req, responder).await;
    assert_eq!(
        info.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );
}

// 3. Test 404 maps to NXDomain
#[tokio::test]
async fn test_resolve_kin_api_404_nxdomain() {
    let api_url = start_mock_daemon().await;
    let handler = KineticDnsHandler::new(api_url);

    let req = build_request("missing.kin.", RecordType::A).await;
    let responses = Arc::new(Mutex::new(Vec::new()));
    let responder = MockResponseHandler {
        responses: responses.clone(),
    };

    let info = handler.handle_request(&req, responder).await;
    assert_eq!(
        info.response_code(),
        hickory_proto::op::ResponseCode::NXDomain
    );
}

// 4. Test 500 maps to ServFail
#[tokio::test]
async fn test_resolve_kin_api_500_servfail() {
    let api_url = start_mock_daemon().await;
    let handler = KineticDnsHandler::new(api_url);

    let req = build_request("500.kin.", RecordType::A).await;
    let responses = Arc::new(Mutex::new(Vec::new()));
    let responder = MockResponseHandler {
        responses: responses.clone(),
    };

    let info = handler.handle_request(&req, responder).await;
    assert_eq!(
        info.response_code(),
        hickory_proto::op::ResponseCode::ServFail
    );
}

// 5. Test invalid payload byte parsing failure falls back to NXDomain
#[tokio::test]
async fn test_resolve_kin_invalid_payload() {
    let api_url = start_mock_daemon().await;
    let handler = KineticDnsHandler::new(api_url);

    let req = build_request("invalid-payload.kin.", RecordType::A).await;
    let responses = Arc::new(Mutex::new(Vec::new()));
    let responder = MockResponseHandler {
        responses: responses.clone(),
    };

    let info = handler.handle_request(&req, responder).await;
    assert_eq!(
        info.response_code(),
        hickory_proto::op::ResponseCode::NXDomain
    );
}

// 6. Test invalid DnsZone payload mapping falls back to NXDomain
#[tokio::test]
async fn test_resolve_kin_invalid_zone() {
    let api_url = start_mock_daemon().await;
    let handler = KineticDnsHandler::new(api_url);

    let req = build_request("invalid-zone.kin.", RecordType::A).await;
    let responses = Arc::new(Mutex::new(Vec::new()));
    let responder = MockResponseHandler {
        responses: responses.clone(),
    };

    let info = handler.handle_request(&req, responder).await;
    assert_eq!(
        info.response_code(),
        hickory_proto::op::ResponseCode::NXDomain
    );
}

// 7. Test subdomain fallback to @ if empty
#[tokio::test]
async fn test_resolve_kin_subdomain_fallback() {
    let api_url = start_mock_daemon().await;
    let handler = KineticDnsHandler::new(api_url);

    let req = build_request("www.test1.kin.", RecordType::A).await; // test1.kin has @ but no www
    let responses = Arc::new(Mutex::new(Vec::new()));
    let responder = MockResponseHandler {
        responses: responses.clone(),
    };

    let info = handler.handle_request(&req, responder).await;
    // Because it doesn't have www and no wildcard (*), it should fallback to NXDomain
    assert_eq!(
        info.response_code(),
        hickory_proto::op::ResponseCode::NXDomain
    );
}

// 8. Test uppercase domain normalization
#[tokio::test]
async fn test_resolve_kin_uppercase() {
    let api_url = start_mock_daemon().await;
    let handler = KineticDnsHandler::new(api_url);

    // We send uppercase test1.KIN. It should normalize and still resolve
    let req = build_request("TEST1.KIN.", RecordType::A).await;
    let responses = Arc::new(Mutex::new(Vec::new()));
    let responder = MockResponseHandler {
        responses: responses.clone(),
    };

    let info = handler.handle_request(&req, responder).await;
    assert_eq!(
        info.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );
}

// 9. Test missing AAAA record when only A exists
#[tokio::test]
async fn test_resolve_kin_wrong_record_type() {
    let api_url = start_mock_daemon().await;
    let handler = KineticDnsHandler::new(api_url);

    let req = build_request("test1.kin.", RecordType::AAAA).await; // only A exists
    let responses = Arc::new(Mutex::new(Vec::new()));
    let responder = MockResponseHandler {
        responses: responses.clone(),
    };

    let info = handler.handle_request(&req, responder).await;
    assert_eq!(
        info.response_code(),
        hickory_proto::op::ResponseCode::NXDomain
    );
}

// 10. Test cache invalidation API
#[tokio::test]
async fn test_cache_invalidation() {
    let api_url = start_mock_daemon().await;
    let handler = KineticDnsHandler::new(api_url);

    // First it's empty
    handler.invalidate_cache("test1.kin").await;

    // Cache miss hits the API
    let req = build_request("test1.kin.", RecordType::A).await;
    let responses = Arc::new(Mutex::new(Vec::new()));
    let responder = MockResponseHandler {
        responses: responses.clone(),
    };

    let info = handler.handle_request(&req, responder).await;
    assert_eq!(
        info.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );

    // Invalidate again
    handler.invalidate_cache("test1.kin").await;
}

#[cfg(test)]
mod fuzzing {
    use super::*;
    use proptest::prelude::*;
    use kinetic_core::types::{DnsZone, Reveal};

    proptest! {
        #[test]
        fn doesnt_crash_on_random_payload_parsing(
            raw_payload in any::<Vec<u8>>()
        ) {
            // Fuzz the JSON parser with pure random bytes
            let _ = serde_json::from_slice::<Reveal>(&raw_payload);
        }

        #[test]
        fn doesnt_crash_on_random_reveal_strings(
            random_string in ".*"
        ) {
            // Pass random utf-8 strings into our DnsZone payload parser
            let _ = DnsZone::parse_payload(random_string.as_bytes());
        }
        
        #[test]
        fn doesnt_crash_on_random_domain_normalization(
            domain in ".*"
        ) {
            let normalized = kinetic_core::types::normalize_name(&domain);
            let _apex = kinetic_core::types::extract_apex_domain(&normalized);
        }
    }
}
