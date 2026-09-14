# kinetic-daemon

## 1. Overview
`kinetic-daemon` is the primary user-facing engine of the Kinetic network. Installed on Windows, macOS, or Linux via the desktop installer, this background service handles everything from domain registration math to in-browser privacy routing.

## 2. Architecture & Responsibilities
Because end-users require a seamless Web3 experience within their standard Web2 browsers (Chrome, Safari), this daemon packs a massive amount of functionality:

1. **The Asynchronous Workers (`services/`)**: Runs background threads to sync the KYN Time Oracle, recalculate Proof-of-Work to avoid Kademlia DHT bans, and listen for Global Action State gossip to automatically halt the daemon during network upgrades.
2. **The Macro API (`api/`)**: Generating VDF proofs for domains takes hours. Instead of blocking HTTP requests, the API immediately returns `task_id`s, allowing the Desktop UI to poll for real-time progress bars while the CPU churns in the background.
3. **The TLS Interceptor (`proxy/`)**: When a user types `https://example.kin` into Chrome, this daemon dynamically generates a spoofed SSL certificate signed by the local OS, decrypts the request, tunnels it through the privacy-preserving Libp2p swarm, and returns it securely to the browser.

## 3. Reading Guide
- `src/api/*`: The HTTP REST endpoints. Start with `mod.rs` to see the routing tree, then look at `macro_api.rs` to understand how heavy asynchronous tasks are returned to the UI.
- `src/services/*`: The background workers. Read `network.rs` to understand the Sybil-resistant hot-swap.
- `src/proxy/*`: The MITM proxy. Start with `http.rs` to understand the traffic cop, and `route_p2p.rs` to see how HTTP requests are packed into Gossip payloads.
- `src/main.rs`: The massive orchestrator boot sequence.

## 4. Taxonomy
This crate is a **Layer 5 Executable**. See [`./LAYER_5.md`](./LAYER_5.md) for architectural constraints.
