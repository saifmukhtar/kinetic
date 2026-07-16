use tracing::info;

/// A cross-platform future that resolves when a shutdown signal is received.
/// Listens for both Ctrl+C (SIGINT) and SIGTERM (Unix).
pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
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
