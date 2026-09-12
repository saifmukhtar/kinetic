use crate::api::Role;
use axum::Json;

/// Initiates a graceful shutdown of the Kinetic daemon.
pub async fn handle_shutdown(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_system() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
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
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_system() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
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

use axum::http::header;
use axum::response::IntoResponse;

/// Exports the local Proxy Root CA certificate for browser installation.
pub async fn handle_get_ca_cert(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
) -> Result<impl IntoResponse, crate::api::error::AppError> {
    if !role.can_system() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    let base_config_dir = kinetic_local::config::get_base_dir();

    let nsp = kinetic_core::constants::NSP_SUFFIX;
    let salt_prefix = &kinetic_core::constants::NETWORK_SALT_HEX[0..4];
    let ca_prefix = format!("{}-{}", nsp, salt_prefix);
    let ca_path = base_config_dir.join(format!("{}.cert.pem", ca_prefix));

    match tokio::fs::read_to_string(&ca_path).await {
        Ok(cert) => {
            let headers = [
                (header::CONTENT_TYPE, "application/x-x509-ca-cert"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"kinetic_root_ca.crt\"",
                ),
            ];
            Ok((headers, cert))
        }
        Err(e) => {
            tracing::error!("Failed to read CA cert from {:?}: {}", ca_path, e);
            Err(crate::api::error::AppError::from(
                kinetic_core::error::RestApiError::NotFound,
            ))
        }
    }
}
