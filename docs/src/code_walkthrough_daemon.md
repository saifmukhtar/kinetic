# Chapter 7: Exhaustive Code Walkthrough (`kinetic-daemon` & `kinetic-cli`)

While `kinetic-core` and `kinetic-vdf` define the strict mathematical laws of the protocol, the `kinetic-daemon` is the engine that actually executes them. It serves as the asynchronous orchestrator, seamlessly juggling local HTTP REST requests, continuous background Sled storage maintenance, Kademlia DHT gossiping, and DNS port interception.

In this chapter, we dissect the execution flow of both the Daemon and its counterpart, the user-facing CLI.

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

Sled is absolutely critical because the daemon must remember which domains it owns even if the server is rebooted. Without persistent storage, a daemon reboot would halt the background Heartbeats, eventually subjecting the user's domains to the Grace-Period Escalation takeover.

### 1.2 Spawning the Background Heartbeat Loop

Once the basic architecture is wired (the P2P swarm and the REST API), the daemon spawns its primary defense mechanism: the continuous Heartbeat loop.

```rust
    // Extract the network client clone to send commands to the DHT thread
    let network_client = network_client.clone();
    let storage_clone = storage.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        let reqwest_client = reqwest::Client::new();

        loop {
            interval.tick().await;

            // 1. Fetch latest Drand Pulse
            let drand_data = fetch_drand(&reqwest_client).await;
            let current_pulse = drand_data.round;

            // 2. Load all active domains from Sled
            let active_domains = storage_clone.get_all_active_domains().unwrap_or_default();
            
            for domain in active_domains {
                // 3. Construct the Heartbeat struct
                let mut heartbeat = Heartbeat {
                    name: domain.clone(),
                    drand_pulse: current_pulse,
                    pubkey: local_pubkey.clone(),
                    signature: vec![],
                };

                // 4. Sign and Broadcast
                let signable = heartbeat.signable_bytes();
                heartbeat.signature = keypair.sign(&signable).to_bytes().to_vec();
                
                let _ = network_client.publish_heartbeat(domain.clone(), heartbeat).await;
            }
        }
    });
```

#### Line-by-Line Breakdown:
* **`tokio::spawn(async move { ... })`**: This spawns a detached asynchronous task. It runs completely independently of the main thread, the DNS proxy, and the Kademlia event loop.
* **`interval.tick().await`**: This enforces the 60-second execution cycle. Unlike `std::thread::sleep`, `tick().await` yields control back to the `tokio` scheduler, ensuring 0% CPU usage while waiting.
* **`fetch_drand(&reqwest_client)`**: The daemon passively monitors the Drand network via standard HTTPS requests.
* **`publish_heartbeat(...)`**: The constructed, signed `Heartbeat` is sent across an `mpsc` (Multi-Producer, Single-Consumer) channel to the `kinetic-network` thread, instructing it to initiate a Kademlia `PUT` operation to the broader DHT swarm.

### 1.3 The Local REST API

To allow the user's CLI tools to communicate with the headless daemon, `kinetic-daemon` binds an `axum` HTTP server to `127.0.0.1:16001`.

```rust
async fn publish_reveal(
    State(state): State<AppState>,
    Json(req): Json<PublishRequest>,
) -> impl IntoResponse {
    let mut reveal = req.reveal;
    
    // Normalize to FQDN (Fully Qualified Domain Name)
    if !reveal.name.ends_with(".kin.") {
        reveal.name = format!("{}.", reveal.name);
    }

    // Persist to Sled for automatic Heartbeats
    let _ = state.storage.save_active_domain(&reveal.name);

    // Send to DHT
    match state.network_client.publish_name(reveal.name.clone(), reveal).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
```

When a user registers a name using the CLI, the CLI executes the massive VDF computation and POSTs the final `Reveal` struct to this endpoint. The daemon saves the name to its local Sled DB (ensuring the `tokio` Heartbeat loop picks it up on the next cycle) and forwards the `Reveal` to the DHT.

---

## 2. The User Interface: `kinetic-cli`

If the Daemon is the async orchestrator, the CLI is the brute-force execution tool. Unlike the daemon, the CLI is highly synchronous and blocking, designed to run once, execute a massive computation, and exit.

When a user executes `cargo run -- register apple.kin 192.168.1.100`, the `Commands::Register` block takes over.

### 2.1 Initiating the Registration Pipeline

```rust
        Commands::Register { name, ip, iterations } => {
            // 1. Normalize to FQDN immediately so the signature matches the daemon
            let fqdn = if !name.ends_with(".kin.") {
                format!("{}.kin.", name.trim_end_matches(".kin"))
            } else {
                name.clone()
            };

            // 2. Fetch latest Drand beacon
            let drand_data = fetch_drand().await?;

            // 3. Construct Commitment
            let salt = [0u8; 32]; // For simplicity in v1
            let challenge_bytes = hex::decode(&drand_data.randomness).unwrap();
            let keypair = load_or_create_keypair()?;
            let pubkey = keypair.verifying_key().to_bytes();
            
            let mut hasher = sha2::Sha256::new();
            hasher.update(fqdn.as_bytes());
            hasher.update(&salt);
            hasher.update(&challenge_bytes);
            hasher.update(&pubkey);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hasher.finalize());
```

The CLI constructs the blind commitment hash precisely matching the mathematical parameters expected by the network's `verify` functions.

### 2.2 The VDF Grind

Once the commitment is constructed, the CLI invokes the `kinetic-vdf` engine.

```rust
            let required_iterations = calculate_required_iterations(&fqdn);
            let actual_iterations = std::cmp::max(iterations, required_iterations);

            info!("Initializing Chia VDF Engine. Generating cryptographic proof...");
            
            // This is a strictly blocking call. The thread will lock here.
            let proof = vdf_engine.evaluate(&Commitment { hash }, actual_iterations)?;
            
            info!("VDF Proof successfully generated!");
```

This is the most critical chokepoint in the entire protocol. `vdf_engine.evaluate` is a blocking FFI call to the C++ Chia engine. 

Depending on the length of `fqdn` and the resultant `actual_iterations`, the CLI will sit on this line of code for seconds, hours, or weeks. The CPU core assigned to this process will pin to 100% utilization, relentlessly executing the $x^{2^T}$ repeated squarings. 

Because the CLI is a separate binary from the daemon, this intense, single-threaded CPU block does not impact the daemon's ability to maintain background heartbeats or serve DNS loopback traffic.

### 2.3 The Signature and Handoff

Once the VDF finally yields the proof bytes, the CLI packages the `Reveal`.

```rust
            let mut reveal = Reveal {
                name: fqdn.clone(),
                payload: ip.as_bytes().to_vec(),
                salt,
                drand_pulse: drand_data.round,
                drand_randomness: drand_data.randomness.clone(),
                iterations: actual_iterations,
                vdf_proof: VdfProof { proof_bytes: proof.proof_bytes },
                pubkey: pubkey.to_vec(),
                signature: vec![],
            };
            
            // Generate the strictly serialized Ed25519 signature
            let signable = reveal.signable_bytes();
            reveal.signature = keypair.sign(&signable).to_bytes().to_vec();
            
            // Post to Daemon
            let req_body = json!({ "reveal": reveal });
            client.post("http://127.0.0.1:16001/publish")
                .json(&req_body)
                .send()
                .await;
```

The CLI calculates the Ed25519 signature over the exact byte array of the payload, finalizing the cryptographic tuple. It hands it off to the local REST API, and exits cleanly. The daemon takes over, persisting the name to Sled and throwing the payload into the hostile arena of the Kademlia DHT.
