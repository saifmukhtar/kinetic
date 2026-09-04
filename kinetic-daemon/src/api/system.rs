use axum::{http::StatusCode, Json};
use crate::api::Role;

/// Initiates a graceful shutdown of the Kinetic daemon.
pub async fn handle_shutdown(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !matches!(role, Role::Admin) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Requires Admin role"})),
        ));
    }

    tracing::info!("Shutdown requested via API. Notifying graceful shutdown signal...");
    kinetic_local::shutdown::API_SHUTDOWN.notify_waiters();

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Graceful shutdown initiated"
    })))
}

/// Restarts the Kinetic daemon using the native service manager.
/// If the daemon is not running as a system service, it will gracefully shut down instead.
pub async fn handle_restart(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !matches!(role, Role::Admin) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Requires Admin role"})),
        ));
    }

    tracing::info!("Restart requested via API. Attempting native service restart...");

    // Try to restart via the native service manager.
    // If it fails (e.g. running via cargo run), just shut down gracefully.
    tokio::spawn(async move {
        // Delay slightly so the HTTP response has time to return
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        
        let label: service_manager::ServiceLabel = format!("{}-daemon", kinetic_core::constants::NSP).parse().unwrap();
        match <dyn service_manager::ServiceManager>::native() {
            Ok(manager) => {
                if let Err(e) = manager.stop(service_manager::ServiceStopCtx { label: label.clone() }) {
                    tracing::warn!("Failed to stop native service: {}. Falling back to graceful shutdown.", e);
                    kinetic_local::shutdown::API_SHUTDOWN.notify_waiters();
                } else {
                    // Systemd/launchd will restart it if configured (Restart=always)
                    // If we explicitly restart:
                    let _ = manager.start(service_manager::ServiceStartCtx { label });
                }
            },
            Err(_) => {
                tracing::warn!("No native service manager detected. Falling back to graceful shutdown.");
                kinetic_local::shutdown::API_SHUTDOWN.notify_waiters();
            }
        }
    });

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Restart initiated"
    })))
}
