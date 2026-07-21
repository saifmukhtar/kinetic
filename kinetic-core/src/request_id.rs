//! Task-local correlation ID for request tracing across asynchronous call trees.
//!
//! Set once at the API/FFI entry boundary and propagated throughout Tokio tasks
//! without requiring manual thread-through in function parameters.

use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(1);

tokio::task_local! {
    static CURRENT_REQUEST_ID: std::sync::Arc<String>;
}

/// Returns the current task-local request ID, or `"no-request-id"` if uninitialized.
pub fn current() -> std::sync::Arc<String> {
    CURRENT_REQUEST_ID
        .try_with(|id| id.clone())
        .unwrap_or_else(|_| std::sync::Arc::new("no-request-id".to_string()))
}

/// Runs future `f` within a new auto-generated request ID scope (`"req-N"`).
pub async fn scope<F: std::future::Future>(f: F) -> F::Output {
    let id = std::sync::Arc::new(format!("req-{}", COUNTER.fetch_add(1, Ordering::Relaxed)));
    CURRENT_REQUEST_ID.scope(id, f).await
}

/// Runs future `f` with an explicit request ID (for propagating HTTP header correlation IDs).
pub async fn scope_with_id<F: std::future::Future>(id: String, f: F) -> F::Output {
    CURRENT_REQUEST_ID.scope(std::sync::Arc::new(id), f).await
}
