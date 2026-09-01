//! Cross-platform async signal handling for graceful node shutdown.
//!
//! Listens for `SIGINT` (Ctrl+C) and `SIGTERM` signals to trigger graceful task termination.

use tracing::info;

/// A cross-platform future that resolves when a shutdown signal (`SIGINT` or `SIGTERM`) is received.
#[cfg(not(target_arch = "wasm32"))]
pub async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    error = ?kinetic_core::error::system::SystemError::SigIntBindingFailed(e.to_string()),
                    "{}",
                    kinetic_core::error::system::SystemError::SigIntBindingFailed(e.to_string()).user_message()
                );
                std::future::pending::<()>().await;
            }
        };
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                tracing::warn!(
                    error = ?kinetic_core::error::system::SystemError::SigTermBindingFailed(e.to_string()),
                    "{}",
                    kinetic_core::error::system::SystemError::SigTermBindingFailed(e.to_string()).user_message()
                );
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Ctrl+C (SIGINT) received, starting graceful shutdown");
        },
        _ = terminate => {
            info!("SIGTERM received, starting graceful shutdown");
        },
    }
}

/// A cross-platform future that resolves when a shutdown signal is received.
/// On WebAssembly, this returns a pending future that never resolves.
#[cfg(target_arch = "wasm32")]
pub async fn shutdown_signal() {
    std::future::pending::<()>().await
}
