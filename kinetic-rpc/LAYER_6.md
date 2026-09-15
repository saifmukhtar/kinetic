# Layer 6: Core Infrastructure & Adapters

## 1. The Hook (Taxonomy)
This crate (`kinetic-rpc`) belongs to **Layer 6: Core Infrastructure & Adapters**. It is an adapter that bridges internal Kinetic domain logic with external transport protocols (HTTP).

## 2. The Core Architectural Rule (The Invariant)
**This crate must depend on `kinetic-core` for its error definitions, but `kinetic-core` must NEVER depend on this crate or know about HTTP status codes.**

`kinetic-rpc` is a strict one-way translation layer. It consumes `kinetic_core::error::*` and outputs serializable JSON structs. 

## 3. The Horizontal Boundary
This crate exclusively owns HTTP semantic mapping (RFC 7807) and async request correlation (`request_id`). 
It explicitly ignores *how* an error occurred. It does not validate identities, verify cryptography, or read from storage. It only cares about mapping an already-failed internal operation to the correct `4xx` or `5xx` HTTP status code.

## 4. Why This Exists (Abstraction Defense)
Isolating HTTP status code mappings here prevents the core Kinetic logic (Layer 5) from being polluted by web server concerns. If Kinetic ever moves away from HTTP REST to gRPC or WebSockets, the core crates (`kinetic-core`, `kinetic-verify`) remain completely untouched; only this translation crate needs to be updated.
