# Crate Contract: `kinetic-nrs`

## 1. Domain Purpose
This is the **Name Resolution & DNS Proxy** boundary (Layer 6). Its singular role is to run a local UDP/TCP DNS server (`127.0.0.1:53`) that translates legacy OS DNS queries into Web3 `.kin` lookups, and forwards standard Web2 queries (`.com`) to upstream resolvers.

## 2. Pre-conditions (What the caller MUST do)
* **Daemon Dependency:** The local `kinetic-daemon` MUST be running and exposing its REST API (e.g., `127.0.0.1:4433`). This crate cannot search the DHT itself; it queries the local daemon for state.
* **OS Configuration:** The user's operating system MUST be configured to use `127.0.0.1` as its primary DNS resolver for this crate to intercept traffic.
* **Root Permissions (Optional):** To bind to the default DNS port (`53`), the caller MUST execute the binary with root privileges. The binary will automatically drop privileges to the `nobody` user after binding.

## 3. Post-conditions & Guarantees (The "Always")
* **Web2 RFC Compliance:** Guarantees that rich Web3 zone files are flattened into legacy-safe DNS payloads (e.g., if a `CNAME` exists, all other records like `KID` or `TXT` are stripped out to prevent OS resolver panics).
* **DNS-Level SSRF Protection:** Guarantees that any `.kin` domain attempting to resolve to a loopback, private, or CGNAT IP address is blocked *before* the user's browser ever attempts a connection (utilizing `validate_ssrf_safe`).
* **E2E Authenticity:** Guarantees that the name record fetched from the local daemon is cryptographically verified against the owner's Identity Document before it is served to the OS.
* **Seamless Internet:** Guarantees that non-`.kin` domains are flawlessly routed to standard upstream resolvers (e.g., Cloudflare/Google).

## 4. Anti-Guarantees (The "Never")
* **Zero State Mutation:** This crate NEVER registers, updates, or revokes a `.kin` name. It is strictly a Read-Only translation proxy.
* **Zero P2P Networking:** This crate NEVER communicates with the libp2p swarm or the global DHT directly. It relies entirely on the Daemon HTTP API.
* **Zero Consensus Math:** This crate NEVER evaluates Proof of Patience (VDF) difficulty or block decay.

## 5. Trust Boundaries & Dependencies
* **Internal:** Fully trusts `kinetic-core` for the SSRF security logic and error definitions.
* **External:** Fully trusts `hickory-dns` for the raw UDP/TCP DNS packet parsing and the OS for privilege isolation (`privdrop`).
