# kinetic-rpc

## 1. Overview
`kinetic-rpc` is the serialization boundary for the Kinetic network's REST APIs. It ensures that all errors returned to client applications strictly adhere to the [RFC 7807 (Problem Details for HTTP APIs)](https://datatracker.ietf.org/doc/html/rfc7807) standard.

## 2. Usage & Integration
This crate is primarily consumed by the HTTP routing handlers in `kinetic-daemon`.

```rust
// Example integration pattern (pseudo-code)
use kinetic_core::error::ResolutionError;
use kinetic_rpc::ApiError;

// Inside an HTTP Handler:
// If an internal core operation fails...
let internal_error = ResolutionError::NotFound { name: "alice.kin".into(), peers_queried: 10 };

// We convert it cleanly to an RFC 7807 JSON response without match-statement spaghetti in the handler.
let response: ApiError = internal_error.into();

assert_eq!(response.status, 404);
assert_eq!(response.title, "Name Not Found");
```

## 3. Internal Architecture
Under the hood, `kinetic-rpc` implements:
*   **Massive `From<T>` Mappings:** The `api_error.rs` file acts as a giant translation matrix, taking dozens of internal errors (like `IdentityError::MalformedManifest`) and mapping them to safe, standardized HTTP responses (like `422 Unprocessable Entity`).
*   **Proxy Leak Defense:** It intentionally strips sensitive internal failures (like a backend KYN Provider returning a 404) and translates them into generic `502 Bad Gateway` errors to prevent clients from misinterpreting internal infra issues as user-level 404s.
*   **Task-Local Tracing:** `request_id.rs` injects an asynchronous correlation ID (`req-N`) into every error, allowing operators to trace a single 500 Internal Server Error down through complex Tokio asynchronous call trees.

## 4. Reading Guide
To fully understand this crate, we recommend reading it in the following order:

### Prerequisites
Before reading this crate, you must understand:
* **kinetic-core:** You must understand the various error enums defined in `kinetic-core::error` (e.g., `IdentityError`, `ResolutionError`, `StorageError`), as this crate maps them.

### File Traversal (Leaf-First)
Read this crate in the following order:
1. `src/request_id.rs` - Understand how the task-local Tokio correlation ID is generated and propagated.
2. `src/api_error.rs` - Look at the `ApiError` struct definition to see the RFC 7807 format, then scroll through the `From` implementations to see how Kinetic domain errors are categorized into HTTP buckets.
3. `src/lib.rs` - The module orchestrator.

## 5. Taxonomy & Links
* **Taxonomy:** This crate belongs to Layer 6. Please read [`./LAYER_6.md`](./LAYER_6.md) to understand the strict architectural constraints of this layer.
* **Repository:** [https://github.com/saifmukhtar/kinetic](https://github.com/saifmukhtar/kinetic)
