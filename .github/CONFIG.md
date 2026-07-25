# Kinetic Configuration Guide

The Kinetic network uses a `config.toml` file to manage local user preferences, networking, and daemon behaviors. 

By default, the daemon generates a clean, minimal configuration file containing only the most essential settings. Advanced users can manually add the hidden settings to their `config.toml` to override the defaults.

---

## `[daemon]`
Settings related to local services, storage, and the HTTP API.

* **`storage_dir`** (✅ **Visible by default**)
  * Path to the directory where the embedded database is stored.
* **`network_mode`** (✅ **Visible by default**)
  * Operating mode (`FullNode` or `LightClient`). Light clients don't store DHT records.
* **`auto_update`** (✅ **Visible by default**)
  * Whether the node should automatically download and install OTA binary updates (`true`/`false`).
* **`ipfs_gateway`** (✅ **Visible by default**)
  * IPFS gateway URL used to resolve `IPFS(cid)` records in the HTTP Proxy.
* **`enable_dns`** (✅ **Visible by default**)
  * Whether to start the built-in UDP DNS resolver on boot (`true`/`false`).
* **`dns_port`** (✅ **Visible by default**)
  * Port for the built-in DNS resolver (Default: `53`).
* **`atlas_port`** (✅ **Visible by default**)
  * UDP port for querying the Kinetic Atlas Bridge daemon (Default: `34291`).

* **`bind_ip`** (👁️ *Hidden by default*)
  * Local IP address to bind to for daemon services (Default: `127.0.0.2`).
* **`api_port`** (👁️ *Hidden by default*)
  * Port for the daemon's authenticated HTTP API.
* **`proxy_port`** (👁️ *Hidden by default*)
  * Port for the built-in HTTP reverse proxy.
* **`backend_port`** (👁️ *Hidden by default*)
  * Port for the local backend HTTP server.
* **`pac_port`** (👁️ *Hidden by default*)
  * Port for the Proxy Auto-Config (PAC) server.

---

## `[network]`
Settings for peer-to-peer (P2P) networking, peer discovery, and listening ports.

* **`bootstrap_nodes`** (✅ **Visible by default**)
  * List of multiaddrs used to initially connect to the Kinetic network.
* **`seed_domain`** (✅ **Visible by default**)
  * List of domains used to discover additional bootstrap peers via DNS.
* **`enable_mdns`** (✅ **Visible by default**)
  * Whether to enable mDNS peer discovery on the local Wi-Fi network.

* **`daemon_port`** (👁️ *Hidden by default*)
  * TCP listening port for the P2P daemon.
* **`daemon_quic_port`** (👁️ *Hidden by default*)
  * QUIC listening port for the P2P daemon.
* **`node_port`** (👁️ *Hidden by default*)
  * TCP listening port for the public P2P node.
* **`node_quic_port`** (👁️ *Hidden by default*)
  * QUIC listening port for the public P2P node.
* **`host_port`** (👁️ *Hidden by default*)
  * TCP listening port for the public P2P host.
* **`host_quic_port`** (👁️ *Hidden by default*)
  * QUIC listening port for the public P2P host.
* **`external_address`** (👁️ *Hidden by default*)
  * Force advertise a specific public multiaddr (useful for public nodes running behind complex NATs).

---

## `[drand]`
Settings for the Drand randomness beacon client.

* **`drand_domain`** (✅ **Visible by default**)
  * Domains to query via DNS TXT records to discover dynamic Drand Quicknet HTTP endpoints.
* **`p2p_only`** (✅ **Visible by default**)
  * If `true`, the node will completely disable HTTP queries to Drand servers and rely strictly on P2P gossip for randomness pulses (great for privacy).

* **`endpoints`** (👁️ *Hidden by default*)
  * List of fallback Drand HTTP API endpoints to query directly if P2P gossip fails.
