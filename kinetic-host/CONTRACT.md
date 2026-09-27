# Binary Contract: `kinetic-host`

## 1. Domain Purpose
This is the **Headless P2P Reverse Proxy Seeder** (Layer 7). Its singular role is to expose a standard local HTTP web server (e.g., NGINX, Apache, Node.js) to the global Kinetic P2P network. It acts as an inbound bridge, translating Libp2p proxy streams into native HTTP requests for the backend server.

## 2. Pre-conditions (What the Developer MUST do)
* **Run a Web Server:** The user MUST execute a standard web server on the local machine (e.g., listening on `127.0.0.1:80`).
* **Configure Backend Port:** The user MUST configure this binary (via the `config` CLI command or `config.toml`) to point to the exact local port the backend web server is listening on.

## 3. Post-conditions & Guarantees (The "Always")
* **Firewall Traversing Ingress:** Guarantees that the backend server is globally accessible via the `.kin` namespace *without* requiring the developer to configure NAT port forwarding or open router firewall ports (utilizing libp2p Hole Punching and Relays).
* **Continuous DHT Seeding:** Guarantees that it continuously publishes its Host Routing Record to the Kademlia DHT, ensuring client daemons can always discover its current IP address and dynamically dial it.
* **HTTP Translation:** Guarantees seamless, bidirectional translation between standard TCP/HTTP requests and Kinetic's internal Libp2p Request/Response proxy protocol.

## 4. Anti-Guarantees (The "Never")
* **Zero Public Routing:** This binary runs in `NetworkMode::Edge`. It NEVER routes DHT queries, bootstraps peers, or relays gossip for other network participants.
* **Zero OS DNS Hijacking:** Unlike the `kinetic-daemon`, this binary NEVER configures the local OS PAC proxy or runs the NRS DNS server. It is purely a traffic receiver, not a client browser orchestrator.
* **Zero Action Plane Mutation:** This binary NEVER executes sovereign state rotations or upgrades. It strictly listens to them to stay synced.

## 5. Trust Boundaries & Dependencies
* **Internal:** Fully trusts `kinetic-network` to securely decrypt and multiplex incoming streams.
* **External:** Fully trusts the local backend web server to respond cleanly to HTTP requests. If the backend crashes, this binary will gracefully return a `502 Bad Gateway` to the P2P swarm.
