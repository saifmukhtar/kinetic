# Crate Contract: `kinetic-rpc`

## 1. Domain Purpose
This is the **HTTP Adapter & Tracing** boundary (Layer 6). Its singular purpose is to translate internal domain errors from the consensus engine into standardized RFC 7807 (Problem Details for HTTP APIs) JSON responses, and to provide asynchronous `request_id` correlation for telemetry.

## 2. Pre-conditions (What the caller MUST do)
* **Execute HTTP Transport:** The caller (the `kinetic-daemon` or `kinetic-node` binary) MUST handle the actual TCP/HTTP socket connections. This crate does not include an HTTP server (e.g., `axum` or `hyper`).
* **Wrap Execution Context:** The caller MUST explicitly wrap incoming web requests inside `kinetic_rpc::request_id::scope` to generate a correlation ID before executing consensus logic.
* **Error Translation:** The caller MUST catch native `kinetic-core` errors and pass them into this crate via `.into()` for translation before sending a response.

## 3. Post-conditions & Guarantees (The "Always")
* **Domain Decoupling:** Guarantees that web-specific concepts (like HTTP Status Codes `404`, `502`, or `400`) never leak into the core mathematical consensus crates.
* **RFC 7807 Compliance:** Guarantees that all API errors follow a predictable, standardized JSON structure for external clients and browser extensions to consume safely.
* **Asynchronous Tracing:** Guarantees that deep, nested asynchronous Tokio tasks will always have access to the original HTTP `request_id` for accurate log aggregation.

## 4. Anti-Guarantees (The "Never")
* **Zero Cryptography:** This crate NEVER executes an ML-DSA-65 verification.
* **Zero Consensus Logic:** This crate NEVER evaluates if an action or name is valid. It simply formats the error string after the consensus engine rejects it.
* **Zero Network I/O:** This crate NEVER opens a socket or reads from the network.

## 5. Trust Boundaries & Dependencies
* **Internal:** Fully trusts `kinetic-core` to provide semantic error enums. 
* **External:** Fully trusts Tokio's task-local storage for managing correlation scopes.
