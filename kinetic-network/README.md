# kinetic-network

**The libp2p network mesh, swarm routing, and Drand entropy client for the Kinetic Network.**

`kinetic-network` is the core P2P communication layer for Kinetic. It orchestrates the underlying `libp2p` swarm, managing global Peer discovery, Kademlia DHT routing, Gossipsub publish/subscribe channels, and CDN acceleration.

It is heavily optimized for Sybil resistance and cryptographic integrity across both native desktop nodes and WASM browser light-clients.

## Features

- **S/Kademlia & Proof-of-Work**: Implements Sybil-resistant Kademlia routing by forcing peers to mine an Argon2id Proof-of-Work block tied to the current Drand entropy epoch before they can join the mesh.
- **Drand Quicknet Client**: Includes an embedded HTTP client (`reqwest` with DNS fallback) that continuously polls the League of Entropy's Drand Quicknet beacon to verify the global clock (Kyn) and seed random numbers.
- **VDF Rate-Limiting**: Integrates with `kinetic-vdf` (RSA-2048) to computationally rate-limit Kademlia `.kin` name registrations. Bad proofs are instantly banned via an ultra-fast `lru` ban cache.
- **WASM Compatible**: Fully compatible with `wasm32-unknown-unknown` via `libp2p-webrtc` and `websocket-websys`, enabling browser-based nodes to participate in the global routing tables.
- **Gossipsub Channels**: Safely validates and propagates Signed Governance Messages and VDF state updates across the entire global network in milliseconds.
- **CDN Backplane**: Features a custom Request/Response protocol that allows caching layer nodes (Hosts) to rapidly serve cryptographic proofs to Light Nodes over WebRTC/TCP.
