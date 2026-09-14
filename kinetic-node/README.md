# kinetic-node

## 1. Overview
`kinetic-node` is a headless Layer 5 public infrastructure executable. It acts as the backbone for the Kinetic network, providing Kademlia DHT bootstrap stability and time oracle ingestion.

**This is NOT a blockchain validator.** It does not mine blocks or construct a global ledger. 

## 2. Architecture & Responsibilities
1. **DHT Bootstrapping:** When starting, the node persists a static Ed25519 keypair (`node_key.rs`) so that its `PeerId` remains stable across AWS/DigitalOcean reboots. User daemons hardcode these peer IDs to join the network.
2. **Time Oracle Bridge:** To prevent 50,000 user laptops from simultaneously slamming external time beacons via HTTP, `kinetic-node` independently queries the KYN Provider, cryptographically verifies the entropy payload, and floods it into the internal `libp2p::gossipsub` mesh (`main.rs`).
3. **High Availability API:** It exposes a minimal `axum` web server (`api.rs`) purely for container orchestration platforms (like Kubernetes) to perform Liveness and Readiness health checks.

## 3. Reading Guide
- `src/main.rs`: The executable entry point. Read the `kyn_provider` and heartbeat instantiation to understand how time is injected into the network.
- `src/gossip.rs`: The mesh flood router. It intercepts Action Upgrades and Time Pulses.
- `src/node_key.rs`: The cryptographic persistence mechanism for cloud identity.
- `src/api.rs`: The `/health` HTTP routes.

## 4. Taxonomy
This crate is a **Layer 5 Executable**. See [`./LAYER_5.md`](./LAYER_5.md) for architectural constraints.
