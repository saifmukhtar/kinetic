# kinetic-node

**The background full-node and bootstrap seed daemon for the Kinetic Network.**

`kinetic-node` serves as the structural backbone of the Kinetic P2P mesh network. While Light Clients and Hosts act on the edges of the network, `kinetic-node` is designed to be deployed as a highly available, long-running daemon on datacenter infrastructure.

These nodes participate heavily in Kademlia routing, VDF verification, and Gossipsub message propagation, ensuring that the network remains robust, censorship-resistant, and securely synchronized to the Drand entropy beacon.

## Features

- **P2P Swarm Backbone**: Initializes a full `kinetic-network` event loop, aggressively caching Kademlia routing tables and serving as a reliable dial-in point (Bootstrap Seed) for other nodes.
- **Drand Synchronization**: Actively listens to the League of Entropy's Quicknet beacon, translating raw entropy into Kinetic Clock (Kyn) epochs and aggressively gossiping verified kyns to peers without outbound internet access.
- **Sovereign Governance**: Listens to the `GOSSIP_TOPIC_GLOBAL` pubsub channel for Signed Governance Messages. It verifies cryptographic signatures against the embedded genesis configuration and mutates the local state database (revoking compromised KIDs, updating schemas, etc.).
- **Forensic Identity Persistence**: Generates a static `Ed25519` cryptographic identity (`node.key`) on first boot and securely locks it to the file system to prevent accidental deletion or corruption.
- **Health-check API**: Hosts a lightweight, unauthenticated `axum` HTTP server (default port `16003`) exposing `/health` and `/peer_id` for external load balancers and Prometheus telemetry scrapers.
- **System Service Management**: Includes an integrated CLI (`start`, `stop`, `install`, `uninstall`) powered by `service-manager` to seamlessly integrate with `systemd` (Linux), `launchd` (macOS), or `Win32 Services` (Windows).

## Infrastructure Deployment

For optimal network health, `kinetic-node` instances should be deployed with fixed public IPs and their Libp2p Multiaddresses should be injected into the `bootstrap_nodes` array of consumer client configurations.
