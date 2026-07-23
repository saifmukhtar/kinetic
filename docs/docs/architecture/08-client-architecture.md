# Architecture & Motivation: Client Architecture

The success of a decentralized protocol depends on its accessibility. If only Linux systems administrators can run a node, the network will never achieve mainstream decentralization.

Kinetic solves this with two distinct client models: The **Tauri Desktop Client** for full nodes, and **WebAssembly (Wasm)** for light clients.

## The Tauri Desktop App (Full Node)

To provide a seamless "one-click install" for Windows, macOS, and Linux users, Kinetic bundles the daemon, the UI, and the local DNS resolver into a **Tauri Desktop Application** (`kinetic-client/desktop/src-tauri`).

### Why Tauri instead of Electron?
Electron bundles an entire Chromium browser and Node.js runtime into every application. This results in massive binaries (hundreds of megabytes) and heavy RAM consumption. 

A Kinetic node is expected to run quietly in the background 24/7 to maintain the DHT and provide local DNS resolution. Using Electron would drain laptop batteries and hog system resources.

Tauri solves this by:
1. **Rust Backend:** The heavy lifting (the P2P DHT, the Argon2id PoW, the VDF, the DNS server) is compiled to highly optimized, memory-safe native Rust.
2. **OS Webviews:** Instead of bundling Chromium, Tauri uses the operating system's native webview (Edge on Windows, WebKit on macOS, WebKitGTK on Linux) to render the UI. 

This results in a tiny binary footprint and near-zero idle resource consumption.

### IPC Isolation
In Tauri, the React frontend runs in the webview, while the Kinetic daemon runs in the Rust core. They communicate via Inter-Process Communication (IPC). This provides a massive security boundary. If the React frontend is compromised via a cross-site scripting (XSS) attack, the attacker is trapped in the webview sandbox and cannot easily access the user's `identity.key` or `reveal.json` proofs stored securely in the Rust backend.

## WebAssembly (Wasm) Light Clients

While the desktop app acts as a full node, web developers need a way to verify Kinetic identities (`did:kin`) and names natively inside web browsers without asking the user to install a desktop app.

To support this, the `kinetic-kid` (identity) and `kinetic-core` crates are compiled to **WebAssembly (Wasm)**.

### The Light-Client Trust Model
In many blockchains, a "light client" just sends an API request to a centralized server (like Infura or Alchemy) and blindly trusts the JSON response. This is essentially centralized Web2.

With Kinetic Wasm clients, the browser might ask a random gateway for the records of `alice.kin`. But the browser does not trust the gateway. The gateway must return the raw data *and the cryptographic VDF/Ed25519 proofs*. 

The Wasm module running in the user's browser then executes the VDF verification and signature math locally. If the gateway lies, the math fails, and the Wasm client rejects the data. This allows browser-based apps to maintain cryptographically guaranteed zero-trust security without needing to sync the entire DHT.
