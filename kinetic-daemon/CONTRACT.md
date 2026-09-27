# Binary Contract: `kinetic-daemon`

## 1. Domain Purpose
This is the **Desktop Orchestrator & Client** (Layer 7). It is the primary executable run by end-users. It coordinates OS-level integration (`kinetic-pac`, `kinetic-nrs`), runs a local Certificate Authority (for HTTPS interception), exposes a Management REST API, and connects to the global network to resolve `.kin` domains.

## 2. Pre-conditions (What the User MUST do)
* **Local Execution:** The user MUST run this application locally on their host machine (Windows, macOS, Linux).
* **OS Permissions:** The user MUST grant the daemon appropriate privileges if they wish to utilize automatic OS DNS hijacking (via `kinetic-nrs` on Port 53) or OS proxy injection (`kinetic-pac`).

## 3. Post-conditions & Guarantees (The "Always")
* **Topological Flexibility:** Guarantees that the P2P swarm can operate as either a pure `NetworkMode::Edge` client or a full `NetworkMode::Router` (bootstrapping and routing DHT traffic for others) based on the user's configuration.
* **Local Control Plane Security:** Guarantees that, regardless of the P2P topology, the Management REST API and the local HTTP Proxy are strictly bound to the configured `bind_ip` (e.g., `127.0.0.1`), preventing unauthorized remote access to the user's node.
* **Dynamic Ephemeral Privacy:** Guarantees that a new, random libp2p `PeerId` is dynamically mined (Proof of Patience) and generated on every startup to prevent the user from being tracked across the global DHT.
* **TLS Bridging:** Guarantees the dynamic generation of trusted, ephemeral SSL certificates (via `ca.rs`) for intercepted `.kin` requests, allowing users to browse Web3 domains without HTTPS security warnings.

## 4. Anti-Guarantees (The "Never")
* **Zero Static Identity:** Unlike `kinetic-node`, this daemon NEVER uses a persistent, static PeerID on disk. 
* **Zero Protocol Math:** This daemon NEVER implements cryptographic math, signature verification, or VDF proofs directly. It delegates all protocol logic to the `kinetic-core` and `kinetic-verify` libraries.

## 5. Trust Boundaries & Dependencies
* **Internal:** The daemon trusts the lower-level adapters (`kinetic-rpc`, `kinetic-storage`, `kinetic-network`) to securely execute its commands.
* **External:** The daemon trusts the host operating system's root certificate store to safely accept its generated `ca.rs` certificates for local HTTPS interception.
