# Crate Contract: `kinetic-core`

## 1. Domain Purpose
This is the **Central Nervous System & Domain Orchestrator** (Layer 5). Its singular role is to define the unified error taxonomy, the mathematical physics engine (VDF difficulty decay), semantic payload validation (DNS/NRS rules), and the abstraction interfaces (traits) for the physical networking and storage adapters.

## 2. Pre-conditions (What the caller MUST do)
* **Dependency Injection:** The caller (the Daemon/Node binary executable) MUST inject concrete implementations for the `StorageEngine`, `P2pNetwork`, and `KynProvider` traits into the core logic loops.
* **Environment Context:** The caller MUST supply the active `KineticConfig` (typically loaded via `kinetic-local`) so the core engine can properly configure difficulty floors and SSRF safety logic.

## 3. Post-conditions & Guarantees (The "Always")
* **Semantic Data Integrity:** Guarantees that parsed payloads obey strict domain business rules before entering state. For example, `NrsZone::validate()` mathematically guarantees that no CNAME record coexists with an A/TXT record (obeying DNS RFCs), and that all string labels are length-bounded.
* **Deterministic Physics:** Guarantees that Proof-of-Patience (VDF) difficulty calculation (`calculate_proof_patience_v2`) uses strict, floating-point-free integer math to prevent multi-architecture consensus splits.
* **SSRF Protection:** Guarantees that IP addresses are strictly filtered via `validate_ssrf_safe`, rejecting loopback, local, CGNAT, and IPv6-mapped-IPv4 exploits at the domain boundary.

## 4. Anti-Guarantees (The "Never")
* **Zero Physical Execution:** This crate NEVER opens a TCP socket, NEVER writes a byte to the hard drive, and NEVER polls a REST endpoint. It exclusively commands the injected trait adapters to do physical I/O.
* **Zero Cryptography:** This crate NEVER directly verifies a signature. It explicitly delegates all authorization checks to `kinetic-verify` and `kinetic-action`.

## 5. Trust Boundaries & Dependencies
* **Internal:** Fully trusts `kinetic-verify` (Layer 4) for signature evaluation and `kinetic-types` (Layer 3) for the raw struct syntax.
* **External:** Fully trusts the outer adapter ring (`kinetic-storage`, `kinetic-network`, `kinetic-local`) to honestly fulfill the contract of the injected traits without panicking.
