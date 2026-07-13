//! Task-local correlation ID for request tracing.
//! Set once at the API/FFI entry boundary; available throughout the entire
//! async task without threading it through every function signature.

use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(1);

tokio::task_local! {
    static CURRENT_REQUEST_ID: std::sync::Arc<String>;
}

/// Returns the current task-local request ID, or "no-request-id" if not set.
pub fn current() -> std::sync::Arc<String> {
    CURRENT_REQUEST_ID
        .try_with(|id| id.clone())
        .unwrap_or_else(|_| std::sync::Arc::new("no-request-id".to_string()))
}

/// Run `f` within a new auto-generated request ID scope.
pub async fn scope<F: std::future::Future>(f: F) -> F::Output {
    let id = std::sync::Arc::new(format!("req-{}", COUNTER.fetch_add(1, Ordering::Relaxed)));
    CURRENT_REQUEST_ID.scope(id, f).await
}

/// Run `f` with an explicit request ID (for propagating IDs from HTTP headers).
pub async fn scope_with_id<F: std::future::Future>(id: String, f: F) -> F::Output {
    CURRENT_REQUEST_ID.scope(std::sync::Arc::new(id), f).await
}
