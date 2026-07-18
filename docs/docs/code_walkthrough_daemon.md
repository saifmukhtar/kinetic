# Chapter 7: Architecture Walkthrough (`kinetic-daemon` & `kinetic-cli`)

While `kinetic-core` defines the strict mathematical laws of the protocol, the `kinetic-daemon` is the engine that executes them. It orchestrates asynchronous local HTTP REST requests, continuous background storage maintenance, Kademlia DHT gossiping, and DNS interception.

In this chapter, we explore the high-level decoupled architecture of the Daemon and the user-facing CLI.

---

## 1. The Asynchronous Orchestrator: `kinetic-daemon`

The daemon is built entirely on the `tokio` asynchronous runtime. To handle massive concurrent network events while serving instantaneous local DNS queries, the architecture has been rigorously decoupled into distinct operational subsystems.

```mermaid
graph TD
    UI[Web UI / Browser] -->|HTTP REST| API[API Server<br/>(api.rs)]
    CLI[kinetic-cli] -->|HTTP REST| API
    
    subgraph Daemon Services
        API --> Storage[(Sled Storage)]
        API --> Network[kinetic-network<br/>Swarm]
        
        CA[Certificate Auth<br/>(ca.rs)] --> Proxy[HTTPS Proxy<br/>(proxy.rs)]
        Proxy --> PAC[PAC File Server<br/>(pac.rs)]
        
        Nostr[Nostr Client<br/>(nostr.rs)] -->|Delegated VDFs| API
    end
```

### 1.1 Decoupled Components
- **`api.rs`**: The core REST API router that serves the React frontend and handles local control commands from the CLI (e.g., identity generation, name registration, service manifests).
- **`proxy.rs` & `ca.rs`**: The proxy engine acts as an HTTP/HTTPS forwarder. It dynamically provisions self-signed TLS certificates on the fly using `ca.rs`, enabling seamless secure connections to `.kin` domains without browser warnings.
- **`pac.rs`**: Serves the Proxy Auto-Configuration (PAC) file required by the OS to route `.kin` traffic gracefully into the Kinetic loopback interface.
- **`nostr.rs`**: An encrypted communication layer (NIP-04) allowing mobile devices to delegate intense VDF computations to the desktop daemon.

### 1.2 Extensive Test Coverage
The Daemon's modularity allows for extremely rigorous, isolated testing. Instead of testing the entire daemon monolithically, each module is backed by comprehensive inline test suites:
- `api_tests.rs`: Validates REST endpoints, JSON schemas, and state persistence.
- `proxy_tests.rs`: Tests HTTP forwarding, TLS termination, and error fallbacks.
- `ca_tests.rs`: Ensures deterministic generation and validation of the local root CA and leaf certificates.

---

## 2. The User Interface: `kinetic-cli`

While the Web UI is user-friendly, the `kinetic-cli` is the powerful command-line execution tool designed to interface directly with the daemon's REST API and orchestrate complex local workflows.

The CLI architecture employs a deeply modular, subcommand-driven structure:

### 2.1 Identity Management (`kinetic-cli identity`)
Handles all aspects of the user's cryptographic Kinetic Identity Document (KID):
* **`create`**: Generates a new Ed25519 identity keypair and persists it securely to the local vault.
* **`show`**: Displays the active KID, public key, and signature algorithms.
* **`export` / `import`**: Securely backs up and restores the identity keystore.

### 2.2 Name Registration Workflow (`kinetic-cli name`)
This is the core execution path that initiates the Two-Phase Commit/Reveal protocol for claiming `.kin` domains.

1. **Phase 1: The Commit & Grind (`kinetic-cli name register example.kin`)**
   * Grabs the latest Drand beacon.
   * Aggressively utilizes local CPU cores to grind the Chia VDF Proof-of-Time.
   * Broadcasts the Phase 1 Hash Commitment to the DHT and waits exactly 32 seconds to lock the timeline.
   * Generates a template `.reveal.json` file in `~/.local/share/kinetic/zones/`.

2. **Phase 2: Configuration & Reveal (`kinetic-cli name publish example.kin`)**
   * Once the template is configured with the target IP or service manifest, the user runs this command.
   * It calculates the Ed25519 signature over the exact payload.
   * Submits the finalized cryptographic tuple to the daemon's API, injecting the payload into the global Kademlia DHT.

### 2.3 Service Manifests (`kinetic-cli service`)
For advanced users operating decentralized web hosts or edge nodes:
* **`init`**: Bootstraps a service manifest template (configuring HTTPS ports, CDN paths, and failover endpoints).
* **`sign`**: Cryptographically binds the service manifest to the user's root KID, preventing spoofing by malicious nodes.
