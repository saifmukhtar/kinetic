# Layer 7: The P2P Swarm & Transport

## 1. The Trunk (Taxonomy)
This crate (`kinetic-network`) is the **absolute Trunk of Layer 7**. It is the most complex infrastructural component in the workspace. 
While `kinetic-vdf` handles math and `kinetic-storage` handles disks, `kinetic-network` orchestrates the entire decentralized peer-to-peer reality of the node. It wraps the Libp2p Swarm into a thread-safe environment.

## 2. The Core Architectural Rule (The Invariant)
**This crate must safely encapsulate all asynchronous state machines and prevent lock contention on the hot path.**

Because `libp2p::Swarm` is fundamentally single-threaded (requiring exclusive mutable access to poll events), this crate absolutely forbids wrapping the Swarm in an `Arc<RwLock>`. Instead, it forces all Layer 8 callers (like `kinetic-daemon` or `kinetic-host`) to communicate via `tokio::sync::mpsc` channels (`NetworkClient`).

## 3. The Horizontal Boundary
This crate explicitly relies on `kinetic-core` for protocol definitions, `kinetic-types` for data structures, and `kinetic-local` for OS-level state (like network halts).
It acts as the final aggregator before the Layer 8 Daemons (`kinetic-daemon`, `kinetic-node`) consume the API.

## 4. Why This Exists (Abstraction Defense)
Isolating the P2P networking into this crate provides three critical defenses:
1. **Thread Safety:** The event loop (`NetworkEventLoop`) runs in a dedicated `tokio::task`. Deadlocks are impossible because no external crate can hold a lock on the Swarm.
2. **Cryptographic Gatekeeping:** The `KineticRecordStore` acts as a hostile interceptor. It prevents foreign Kademlia DHT payloads from touching the `kinetic-storage` disk unless they pass pure mathematical verification (VDFs, Signatures, KYN timestamps).
3. **Consensus Resolution:** The network layer autonomously resolves collisions via XOR distance metrics without bothering the user-facing CLI or daemon.
