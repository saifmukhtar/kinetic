# kinetic-host

## 1. Overview
`kinetic-host` is a headless Layer 5 payload seeding executable. It is designed to be run via `systemd` or Docker by users who want to host `.kin` domains and serve content 24/7 without needing the heavy interactive UI of the `kinetic-daemon`.

## 2. Architecture & Responsibilities
1. **Dynamic Sybil Resistance (`epoch.rs`):** To prevent DHT spam, the network enforces that all routing nodes complete a heavy Proof-of-Work bound to the current time epoch. As time advances, the PoW expires. `kinetic-host` runs a background heartbeat that preemptively mines the *next* epoch's PoW, and seamlessly hot-swaps the underlying Libp2p Swarm identity without terminating active user connections.
2. **Static Domain Identity (`host_key.rs`):** While the P2P identity rotates constantly, the host maintains a static Ed25519 `host.key` on disk. This is used to sign `HostRoutingRecord`s and publish them to the DHT, allowing clients to always locate the host's current ephemeral peer ID.
3. **Ingress Reverse Proxy (`proxy.rs`):** It acts as an ingress router, intercepting incoming `.kin` P2P privacy-routed requests and transparently tunneling them to a backend HTTP server running locally on the same machine.

## 3. Reading Guide
- `src/main.rs`: The executable entry point. Start here to see how the proxy server and the hot-swap loop are spawned together.
- `src/epoch.rs`: The heartbeat loop that monitors the KYN Time Oracle and orchestrates the identity swap.
- `src/proxy.rs`: The actual request/response tunneling logic connecting Libp2p to local HTTP sockets.
- `src/gossip.rs`: Intercepts emergency network pauses and halts the seeding if required.

## 4. Taxonomy
This crate is a **Layer 5 Executable**. See [`./LAYER_5.md`](./LAYER_5.md) for architectural constraints.
