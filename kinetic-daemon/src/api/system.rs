use crate::api::Role;
use axum::{Json, http::StatusCode};

/// Initiates a graceful shutdown of the Kinetic daemon.
pub async fn handle_shutdown(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !role.can_system() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Requires System or Admin role"})),
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
    if !role.can_system() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Requires System or Admin role"})),
        ));
    }

    tracing::info!("Restart requested via API. Notifying graceful shutdown signal...");

    // Set the flag so main.rs exits with code 1 after graceful shutdown
    kinetic_local::shutdown::RESTART_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
    kinetic_local::shutdown::API_RESTART.notify_waiters();

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Restart initiated"
    })))
}
