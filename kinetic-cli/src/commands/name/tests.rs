use super::NameCommands;
use super::handle_name_command;
use axum::{Router, routing::get};
use kinetic_core::config::KineticConfig;
use reqwest::Client;
use tokio::net::TcpListener;

#[tokio::test]
async fn test_name_resolve_mock_api() {
    // Removed unused channel

    let app = Router::new().route(
        "/resolve/{name}",
        get(
            |axum::extract::Path(name): axum::extract::Path<String>| async move {
                if name == format!("test{}", kinetic_core::constants::NSP_SUFFIX) {
                    axum::response::Response::builder()
                        .status(200)
                        .body(axum::body::Body::from("mocked data"))
                        .unwrap()
                } else {
                    axum::response::Response::builder()
                        .status(404)
                        .body(axum::body::Body::from("not found"))
                        .unwrap()
                }
            },
        ),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut config = KineticConfig::default();
    config.daemon.api_port = port;

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::new();

    // Resolve successfully
    let cmd = NameCommands::Resolve {
        name: format!("test{}", kinetic_core::constants::NSP_SUFFIX),
    };
    let res = handle_name_command(cmd, &config, &client).await;
    assert!(res.is_ok());

    // Resolve not found
    let cmd2 = NameCommands::Resolve {
        name: format!("invalid{}", kinetic_core::constants::NSP_SUFFIX),
    };
    let res2 = handle_name_command(cmd2, &config, &client).await;
    assert!(res2.is_ok()); // Logs error but doesn't fail process
}

#[tokio::test]
async fn test_name_publish_no_zone() {
    let config = KineticConfig::default();
    let client = Client::new();
    // Trying to publish a name that we haven't registered
    let cmd = NameCommands::Publish {
        name: format!("nonexistent{}", kinetic_core::constants::NSP_SUFFIX),
    };
    let res = handle_name_command(cmd, &config, &client).await;
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("No zone file found"));
}
