use anyhow::Result;
use axum::{
    body::Body,
    extract::{Request, State},
    response::Response,
    routing::any,
    Router,
};
use kinetic_network::{client::ProxyRequest, NetworkConfig, NetworkEventLoop, NetworkMode};
use kinetic_storage::SledStorage;
use std::sync::Arc;
use tokio::sync::watch;

async fn fetch_drand_pulse() -> u64 {
    let client = reqwest::Client::new();
    if let Ok(res) = client.get("https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest").send().await {
        if let Ok(json) = res.json::<serde_json::Value>().await {
            if let Some(round) = json["round"].as_u64() {
                return round;
            }
        }
    }
    0 // Fallback
}

#[derive(Clone)]
struct GatewayState {
    client: kinetic_network::NetworkClient,
    target_peer: libp2p::PeerId,
}

async fn handle_request(
    State(state): State<GatewayState>,
    req: Request<Body>,
) -> Result<Response<Body>, axum::http::StatusCode> {
    let method = req.method().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|x| x.as_str())
        .unwrap_or("/")
        .to_string();

    let mut headers = std::collections::HashMap::new();
    for (k, v) in req.headers() {
        if let Ok(v_str) = v.to_str() {
            headers.insert(k.as_str().to_string(), v_str.to_string());
        }
    }
    // Force Host header for virtual hosting test
    headers.insert(
        "Host".to_string(),
        format!("{}{}", "saif", kinetic_core::types::DOT_TLD),
    );

    use http_body_util::BodyExt;
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes().to_vec())
        .unwrap_or_default();

    let proxy_req = ProxyRequest {
        method,
        path,
        headers,
        body: body_bytes,
    };

    match state
        .client
        .send_proxy_request(state.target_peer, proxy_req)
        .await
    {
        Ok(proxy_res) => {
            let mut builder = Response::builder().status(proxy_res.status);
            for (k, v) in proxy_res.headers {
                builder = builder.header(k, v);
            }
            builder
                .body(Body::from(proxy_res.body))
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(_) => Err(axum::http::StatusCode::BAD_GATEWAY),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let current_pulse = fetch_drand_pulse().await;
    println!("Mining PoW to satisfy kinetic-host anti-spam...");
    let key = kinetic_network::pow::mine_sybil_keypair(
        current_pulse,
        kinetic_network::pow::DEFAULT_DIFFICULTY_BITS,
    );
    let storage = Arc::new(SledStorage::new("/tmp/kinetic_gateway_db")?);

    let config = NetworkConfig {
        mode: NetworkMode::LightClient,
        listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
        bootstrap_nodes: vec![
            "/ip4/127.0.0.1/tcp/6071/p2p/12D3KooWHQaKKkjWdHnnhK78CQkLVQRB9GYoLMAttTbJtdgyizWS"
                .to_string(),
        ],
        seed_domains: vec![],
        enable_mdns: false,
        initial_drand_pulse: 0,
        external_address: None,
    };

    let (incoming_tx, _) = tokio::sync::mpsc::channel(32);
    let (_, rx) = watch::channel(0);

    let (client, loop_task) =
        NetworkEventLoop::new(config, key, storage, rx, Some(incoming_tx), None)?;
    tokio::spawn(loop_task.run());

    let target_peer = "12D3KooWHQaKKkjWdHnnhK78CQkLVQRB9GYoLMAttTbJtdgyizWS"
        .parse()
        .unwrap();
    let state = GatewayState {
        client,
        target_peer,
    };

    let app = Router::new()
        .route("/", any(handle_request))
        .route("/*path", any(handle_request))
        .with_state(state);

    let addr = "127.0.0.1:9999";
    println!("============================================================");
    println!("🌐 HTTP to P2P Gateway is running!");
    println!(
        "🌐 Open your standard web browser and go to: http://{}",
        addr
    );
    println!("============================================================");

    let mut listener = None;
    for _ in 0..10 {
        if let Ok(l) = tokio::net::TcpListener::bind(addr).await {
            listener = Some(l);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let listener = listener.ok_or_else(|| anyhow::anyhow!("Failed to bind to {}", addr))?;
    axum::serve(listener, app).await?;

    Ok(())
}
