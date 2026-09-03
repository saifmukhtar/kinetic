# Kinetic RPC

Public REST API error mapping and distributed tracing utilities for the Kinetic Network.

## Architecture

This is a lightweight utility crate designed to act as a translation layer between internal network operations and public-facing HTTP responses.

**Key Components:**
- **Standardized API Errors (`ApiError`):** Intercepts deep internal errors (like `StorageError` or `P2pError` from `kinetic-core`) and safely translates them into JSON-serializable `ApiError` objects. This ensures that internal stack traces or sensitive local disk paths are never accidentally leaked to external REST clients.
- **Distributed Tracing (`request_id`):** Provides a `tokio::task_local!` correlation ID injection system. This allows asynchronous HTTP requests to be tracked flawlessly across thread boundaries and complex async call trees in the log outputs.
