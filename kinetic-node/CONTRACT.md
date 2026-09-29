# Binary Contract: `kinetic-node`

## 1. Domain Purpose
This is the **Public Infrastructure Application** (Layer 7). Its singular role is to run headlessly on a cloud server, acting as a highly available `NetworkMode::Router` for the global `libp2p` DHT. It bootstraps new peers, relays Gossipsub traffic, and executes the Time Oracle (Beacon) provider.

## 2. Pre-conditions (What the DevOps User MUST do)
* **Public Accessibility:** The user MUST run this binary on a host with a publicly routable IP address and ensure the DHT port (e.g., `16001`) is open through all firewalls.
* **Static Identity Protection:** The user MUST securely back up and protect the `~/.kinetic/node.key` file. Unlike ephemeral clients, infrastructure nodes use static Peer IDs to build long-term reputation in the Kademlia routing tables.

## 3. Post-conditions & Guarantees (The "Always")
* **Headless Background Execution:** Guarantees that it can cleanly install and manage itself as a native OS background daemon (via systemd or launchd) using the `start`, `stop`, and `install` CLI commands.
* **Network Backbone Routing:** Guarantees that it actively participates in the Kademlia DHT routing tables (unlike `NetworkMode::Edge` clients which only leech).
* **Action Plane Synchronization:** Guarantees that it actively listens to the global Gossipsub network for `SignedNetworkAction` broadcasts (e.g., Sovereign Key rotations) and securely persists them to disk to stay perfectly in sync with network governance.

## 4. Anti-Guarantees (The "Never")
* **Zero Client Web Services:** This node NEVER runs the NRS DNS server (`127.0.0.1:53`) and NEVER configures the OS PAC proxy. It is purely designed for network infrastructure, not local web browsing.
* **Zero User Interface:** This node NEVER serves the frontend Web UI. Its REST API is strictly limited to `/health` and `/peer_id` for Kubernetes/Docker liveness probes.
* **Zero Identity Management:** This node NEVER generates or manages user W3C Identity Documents (KIDs). 

## 5. Trust Boundaries & Dependencies
* **Internal:** Fully trusts the entire stack of Kinetic libraries (`kinetic-network`, `kinetic-core`, `kinetic-verify`, etc.) to securely handle all the mathematics and protocol routing.
* **External:** Operates under the assumption that it is running in a hostile public internet environment, relying on `kinetic-core` to drop SSRF attacks and `kinetic-network` to drop spam.
