# kinetic-network

## 1. Overview
`kinetic-network` is the massive Layer 7 infrastructural trunk that drives the Kinetic identity naming network. It houses the entire `libp2p` P2P mesh, managing Distributed Hash Table (DHT) state, high-speed Gossipsub floods, AutoNAT traversals, and cryptographic record verification.

## 2. Usage & Integration
Layer 8 executables (`kinetic-daemon`, `kinetic-node`) do not interact with the Swarm directly. They construct a `NetworkClient` handle and pass messages to the background event loop.

```rust
// Example Integration
use kinetic_network::client::{NetworkClient, NetworkConfig, NetworkMode};
use kinetic_network::event_loop::NetworkEventLoop;
use kinetic_storage::KineticStorage;

// 1. Configure the network mode (Router serving DHT vs Edge Node)
let config = NetworkConfig {
    mode: NetworkMode::Router,
    listen_addresses: vec!["/ip4/0.0.0.0/tcp/16000".parse().unwrap()],
    ..Default::default()
};

// 2. Build the event loop and thread-safe client
let (client, event_loop) = NetworkEventLoop::new(config, storage, vdf_engine);

// 3. Spawn the core Swarm router into a dedicated task
tokio::spawn(async move {
    event_loop.run().await;
});

// 4. Send asynchronous commands safely
let current_kyn = client.get_current_kyn().await.unwrap();
```

## 3. Internal Architecture & The Threat Model
Because `kinetic-network` is exposed directly to the public internet, it employs severe defensive mechanisms:
*   **The Kademlia Interceptor (`src/store/core.rs`):** Standard Libp2p nodes blindly accept DHT records. Kinetic uses a custom `KineticRecordStore` that acts as a hostile gatekeeper, forcing every incoming packet to cryptographically prove its right to exist (VDF difficulty, Signature, and KYN Oracle freshness) before persisting to disk.
*   **XOR Collision Rule (`src/event_loop/utils.rs`):** If two users submit mathematically valid reveals for the exact same namespace simultaneously, the network deterministically selects a winner using the closest XOR numerical distance between the Domain Hash and the Public Key.
*   **MPSC Channel Isolation (`src/client/core.rs`):** The network avoids catastrophic lock contention during Gossipsub floods by isolating the `tokio::select!` event loop and forcing all interactions through a bounded channel.

## 4. Reading Guide
To fully understand this crate, we recommend reading it in the following order:

### Prerequisites
* **kinetic-core:** You must understand `NrsZone`, `Kyn`, and `NameRecord` structures.
* **kinetic-local:** You should understand `GLOBAL_ACTION_STATE` (which dictates emergency network pauses).
* **kinetic-verify:** You must understand how identity signatures are validated.

### File Traversal (Leaf-First)
Read this crate in the following order to build understanding from the bottom up:
1. `src/pow.rs` & `src/dns_tree.rs` - Start with the isolated utilities (Proof of Work calculations and namespace tree mapping).
2. `src/store/verification.rs` - The strict mathematical rules that reject bad network payloads.
3. `src/store/handlers.rs` & `src/store/core.rs` - The Kademlia Interceptor that enforces commit-reveal timelocks and applies the verification rules.
4. `src/client/core.rs` - Understand the `NetworkClient` thread-safe boundary and `mpsc` command orchestrator.
5. `src/behavior.rs` - See how `Kademlia`, `Gossipsub`, and `AutoNAT` are bundled together.
6. `src/event_loop/handlers/*` - The subsystem dispatchers (routing Kademlia vs Gossipsub vs CDN traffic).
7. `src/event_loop/core.rs` - Finally, read the massive `NetworkEventLoop::run` loop that ties the entire network together.

## 5. Taxonomy & Links
* **Taxonomy:** This crate belongs to Layer 7 (Trunk). Please read [`./LAYER_7.md`](./LAYER_7.md) to understand the strict architectural constraints of this layer.
* **Repository:** [https://github.com/saifmukhtar/kinetic](https://github.com/saifmukhtar/kinetic)
