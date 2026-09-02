# kinetic-host

**The HTTP-to-P2P load balancing proxy and CDN edge node for the Kinetic Network.**

`kinetic-host` acts as the critical bridge between the standard web (HTTP) and the Kinetic P2P mesh network. It serves as a local load-balancing proxy that standard browsers can connect to, securely tunneling traffic over the Kademlia DHT and requesting verifiable web bundles from peers on the mesh.

## Features

- **HTTP-to-P2P Proxy**: Runs a local Axum HTTP server that intercepts `.kin` domain requests (configured via the OS by `kinetic-pac`). It transparently resolves the NameRecord and streams the cryptographic WebBundle (or API request) back to the user's browser via `libp2p`.
- **Master/Worker Multiplexing**: Implements a lock-free Master-Worker architecture. Multiple `kinetic-host` instances can run on the same machine to maximize bandwidth and CPU utilization. The first instance binds to the primary proxy port, becoming the "Master", while subsequent instances gracefully degrade into background "Workers" and register their Peer IDs via IPC.
- **CDN Edge Caching**: As traffic routes through the host, it acts as an intelligent edge cache. It validates and temporarily stores verifiable payloads locally using `kinetic-storage`, accelerating resolution speeds for subsequent requests on the local machine and for other peers dialing in.
- **Browser Gateway**: Includes the `browser_gateway` binary, allowing users to spin up temporary HTTP gateways that route traffic to the P2P mesh without modifying OS-level proxy settings, which is incredibly useful for testing and debugging.
- **Ping Proxy Utility**: Provides a CLI (`ping_proxy`) for low-latency ICMP-style health checks across the P2P mesh.
