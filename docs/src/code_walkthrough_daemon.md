# Chapter 7: Exhaustive Code Walkthrough (`kinetic-daemon`, `kinetic-cli` & `kinetic-ui`)

While `kinetic-core` and `kinetic-vdf` define the strict mathematical laws of the protocol, the `kinetic-daemon` is the engine that actually executes them. It serves as the asynchronous orchestrator, seamlessly juggling local HTTP REST requests, serving the React `kinetic-ui`, continuous background Sled storage maintenance, Kademlia DHT gossiping, and DNS port interception.

In this chapter, we dissect the execution flow of the Daemon, the Web UI, and the user-facing CLI.

---

## 1. The Asynchronous Orchestrator: `kinetic-daemon`

The daemon is built entirely on the `tokio` asynchronous runtime. Because it must handle thousands of simultaneous Kademlia network events while simultaneously serving instantaneous local DNS queries, a thread-blocking architecture would instantly collapse under the load.

### 1.1 Initialization and The Storage Engine

When the `kinetic-daemon` binary is executed, it first initializes the local state.

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Initialize Sled Storage
    let storage_dir = "/tmp/kinetic_db";
    let storage = SledStorage::new(storage_dir)?;
    info!("Storage engine initialized at {}", storage_dir);

    // 2. Load or Create Daemon Identity
    let keypair = load_or_create_keypair()?;
    let local_pubkey = keypair.verifying_key().to_bytes();
    info!("Daemon identity loaded: {:?}", hex::encode(local_pubkey));
```

The daemon relies heavily on `kinetic-storage` (a wrapper around the `sled` crate). Sled is an embedded, high-performance database written entirely in Rust. It functions similarly to SQLite but is optimized for massive concurrent throughput. 

Sled is absolutely critical because the daemon must remember which domains it owns even if the server is rebooted. Without persistent storage, a daemon reboot would halt the background Heartbeats (Reveal rebroadcasts), eventually subjecting the user's domains to the Grace-Period Escalation takeover.

### 1.2 Spawning the Background Heartbeat Loop (Reveal Rebroadcast)

Once the basic architecture is wired (the P2P swarm and the REST API), the daemon spawns its primary defense mechanism: the continuous Heartbeat loop. Instead of computing new heartbeats, it continuously rebroadcasts the original valid `Reveal` struct.

```rust
    // Extract the network client clone to send commands to the DHT thread
    let network_client = network_client.clone();
    let storage_clone = storage.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;

            // 1. Load all active Reveal payloads from Sled
            let active_reveals = storage_clone.get_all_active_reveals().unwrap_or_default();
            
            for reveal in active_reveals {
                // 2. Rebroadcast to the DHT (Active territory defense)
                let _ = network_client.publish_reveal(reveal.name.clone(), reveal).await;
            }
        }
    });
```

#### Line-by-Line Breakdown:
* **`tokio::spawn(async move { ... })`**: This spawns a detached asynchronous task. It runs completely independently of the main thread, the DNS proxy, and the Kademlia event loop.
* **`interval.tick().await`**: This enforces the 60-second execution cycle. Unlike `std::thread::sleep`, `tick().await` yields control back to the `tokio` scheduler, ensuring 0% CPU usage while waiting.
* **`publish_reveal(...)`**: The `Reveal` is sent across an `mpsc` channel to the `kinetic-network` thread, instructing it to initiate a Kademlia `PUT` operation to the broader DHT swarm.

### 1.3 The Local Axum Server & The PAC File

The `kinetic-daemon` binds an `axum` HTTP server to `127.0.0.1:16001`. A critical function of this port is to serve the PAC file (`proxy.pac`) required for the **Split-DNS Loopback**. This PAC file instructs the operating system to route all `.kin` domain requests directly to the daemon's local resolver, while passing standard internet traffic through normally.

Additionally, this server hosts the REST API endpoints necessary for managing VDF delegation, publishing zones, and querying the network. The compiled React SPA (`kinetic-ui`) is also served from this API as a fallback, acting as a zero-install graphical control panel for inspecting DHT peers, managing DNS zone files, and tracking Hashcash PoW progress.

---

## 2. The User Interface: `kinetic-cli`

While the Web UI is user-friendly, the `kinetic-cli` is the execution tool designed to initiate the Two-Phase Commit/Reveal workflow.

### 2.1 Phase 1: The Commit & Grind (`kinetic-cli register`)

When a user executes `kinetic-cli register apple.kin`, the CLI handles the first phase:

1.  **Fetch Drand**: Grabs the latest Drand beacon.
2.  **Commit**: Broadcasts the Phase 1 Commitment to the DHT.
3.  **Grind**: Initializes the Chia VDF Engine and computes the proof.
4.  **Template**: Generates and saves a JSON template to `~/.config/kinetic/zones/`.

This is the most critical chokepoint in the entire protocol. Depending on the length of the domain, the CLI will aggressively utilize the CPU to compute the proof.

### 2.2 Phase 2: Configuration & Reveal (`kinetic-cli publish`)

Once the VDF yields the proof bytes, it writes a template JSON file to the user's disk. The user opens this JSON file, modifies the DNS records (e.g., pointing the `A` record to their IP address), and then runs `kinetic-cli publish apple.kin`.

The CLI calculates the Ed25519 signature over the exact byte array of the payload (which now includes the user's IP address), finalizing the cryptographic tuple. It hands it off to the local REST API, and exits cleanly. The daemon takes over, persisting the name to Sled and throwing the payload into the hostile arena of the Kademlia DHT.
