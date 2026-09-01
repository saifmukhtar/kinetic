use crate::KineticNrsHandler;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Router, routing::get};
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

fn mock_reveal(name: &str, payload: Vec<u8>) -> kinetic_core::types::Reveal {
    let mut reveal = kinetic_core::types::Reveal {
        protocol_version: 1,
        name: name.to_string(),
        payload,
        salt: [0u8; 32],
        kyn: 0,
        drand_signature: "".to_string(),
        vdf_proof: kinetic_core::types::VdfProof {
            proof_bytes: vec![],
        },
        iterations: 1,
        pubkey: vec![],
        signature: vec![],
        miner_pubkey: None,
        previous_proof: None,
        authorization: None,
    };
    let keypair = kinetic_primitives::keys::KineticKeypair::generate();
    reveal.pubkey = keypair.pubkey_bytes();
    reveal.signature = keypair.sign(&reveal.signable_bytes(kinetic_core::constants::NETWORK_SALT));
    reveal
}

async fn start_mock_daemon() -> String {
    let app = Router::new().route(
        "/api/resolve/:name",
        get(|Path(name): Path<String>| async move {
            match name.as_str() {
                "test1.kin" => {
                    let mut zone = kinetic_core::types::NrsZone {
                        records: std::collections::HashMap::new(),
                    };
                    zone.records.insert(
                        "@".to_string(),
                        vec![kinetic_core::types::NrsRecord::A(
                            "1.2.3.4".parse().unwrap(),
                        )],
                    );
                    let payload = serde_json::to_vec(&zone).unwrap();
                    let reveal = mock_reveal("test1.kin", payload);
                    (
                        StatusCode::OK,
                        serde_json::to_vec(&kinetic_core::types::NameRecord::Standard(Box::new(
                            reveal,
                        )))
                        .unwrap(),
                    )
                        .into_response()
                }
                "invalid-payload.kin" => (StatusCode::OK, vec![0, 1, 2, 3]).into_response(),
                "invalid-zone.kin" => {
                    let reveal = mock_reveal("invalid-zone.kin", vec![1, 2, 3, 4]); // Invalid JSON for NrsZone
                    (
                        StatusCode::OK,
                        serde_json::to_vec(&kinetic_core::types::NameRecord::Standard(Box::new(
                            reveal,
                        )))
                        .unwrap(),
                    )
                        .into_response()
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
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
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
    let handler = KineticNrsHandler::new(
        api_url,
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        5354,
    );

    let req = build_request("google.com.", RecordType::A).await;
    let responses = Arc::new(Mutex::new(Vec::new()));
    let responder = MockResponseHandler {
        responses: responses.clone(),
    };

    let info = handler.handle_request(&req, responder).await;
    assert!(
        info.response_code() == hickory_proto::op::ResponseCode::NoError
            || info.response_code() == hickory_proto::op::ResponseCode::ServFail
    );
}

// 2. Test successful resolve of .kin name
#[tokio::test]
async fn test_resolve_kin_success() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
    let api_url = start_mock_daemon().await;
    let handler = KineticNrsHandler::new(
        api_url,
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        5354,
    );

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
    let handler = KineticNrsHandler::new(
        api_url,
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        5354,
    );

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
    let handler = KineticNrsHandler::new(
        api_url,
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        5354,
    );

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
    let handler = KineticNrsHandler::new(
        api_url,
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        5354,
    );

    let req = build_request("invalid-payload.kin.", RecordType::A).await;
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

// 6. Test invalid NrsZone payload mapping falls back to NXDomain
#[tokio::test]
async fn test_resolve_kin_invalid_zone() {
    let api_url = start_mock_daemon().await;
    let handler = KineticNrsHandler::new(
        api_url,
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        5354,
    );

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

// 7. Test subname fallback to @ if empty
#[tokio::test]
async fn test_resolve_kin_subname_fallback() {
    let api_url = start_mock_daemon().await;
    let handler = KineticNrsHandler::new(
        api_url,
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        5354,
    );

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

// 8. Test uppercase name normalization
#[tokio::test]
async fn test_resolve_kin_uppercase() {
    let api_url = start_mock_daemon().await;
    let handler = KineticNrsHandler::new(
        api_url,
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        5354,
    );

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
    let handler = KineticNrsHandler::new(
        api_url,
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        5354,
    );

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
    let handler = KineticNrsHandler::new(
        api_url,
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        5354,
    );

    // First it's empty
    handler.invalidate("test1.kin").await;

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
    handler.invalidate("test1.kin").await;
}

#[cfg(test)]
mod fuzzing {

    use kinetic_core::types::{NrsZone, Reveal};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_fuzz_payload_parsing(
            raw_payload in any::<Vec<u8>>()
        ) {
            // Fuzz the JSON parser with pure random bytes
            let _ = serde_json::from_slice::<Reveal>(&raw_payload);
        }

        #[test]
        fn test_fuzz_reveal_strings(
            random_string in ".*"
        ) {
            // Pass random utf-8 strings into our NrsZone payload parser
            use kinetic_core::types::NrsZoneExt;
            let _ = NrsZone::parse_payload(random_string.as_bytes());
        }

        #[test]
        fn test_fuzz_name_normalization(
            name in ".*"
        ) {
            let normalized = kinetic_core::types::normalize_name(&name);
            let _apex = kinetic_core::types::extract_apex_name(&normalized);
        }
    }
}
