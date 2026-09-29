# Crate Contract: `kinetic-network`

## 1. Domain Purpose
This is the **P2P Transport & Swarm** boundary (Layer 6). Its singular purpose is to abstract the complexities of the global `libp2p` network (TCP/QUIC transport, Noise encryption, Kademlia DHT, Gossipsub) into a clean, asynchronous message-passing client (`NetworkClient`) for the core orchestrator to use.

## 2. Pre-conditions (What the caller MUST do)
* **Dependency Injection:** The caller MUST inject fully instantiated implementations of the `StorageEngine` (for the DHT database) and `VdfEngine` (for Proof of Patience verification) during swarm initialization.
* **Task Management:** The caller MUST spawn a dedicated asynchronous Tokio task to run the `NetworkEventLoop` indefinitely, preventing the swarm from starving.
* **Command Passing:** The caller MUST interact with the global network exclusively by passing abstract commands through the `NetworkClient` channel.

## 3. Post-conditions & Guarantees (The "Always")
* **Transport Abstraction:** Guarantees that all underlying connection upgrades (TCP/QUIC fallback, Noise handshake, Yamux stream multiplexing) are handled automatically and securely.
* **Edge Defense (DHT Validation):** Guarantees that any incoming DHT `put` request is intercepted and aggressively verified (schema validation, signature verification, VDF checks) *before* it is ever written to the local storage engine. Malicious or spam records are dropped at the network edge.
* **Topology Enforcement:** Guarantees strict roles between `NetworkMode::Edge` (purely leeching/querying clients that do not route traffic) and `NetworkMode::Router` (publicly reachable nodes that bootstrap the network and relay gossip).

## 4. Anti-Guarantees (The "Never")
* **Zero OS Hijacking:** This crate NEVER attempts to configure the host operating system's DNS or Proxy settings (that is the job of `kinetic-nrs` and `kinetic-pac`).
* **Zero Direct File I/O:** This crate NEVER writes to the filesystem directly. All persistence is routed blindly through the injected `StorageEngine`.
* **Zero Consensus Math Implementation:** While it triggers verification, this crate NEVER implements the ML-DSA-65 math or the Wesolowski VDF itself. It relies entirely on the lower layers.

## 5. Trust Boundaries & Dependencies
* **Internal:** Fully trusts `kinetic-core` for error mappings and `kinetic-verify` for the actual mathematical signature checks.
* **External:** Fully trusts `rust-libp2p` to correctly implement the networking RFCs without leaking memory or crashing on malformed TCP packets.
