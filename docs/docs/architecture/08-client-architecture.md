---
title: '08 — Client Architecture'
prev:
  text: '07 — Governance'
  link: '/architecture/07-governance'
next:
  text: '09 — Forks & Compilation'
  link: '/architecture/09-forks-and-compilation'
---

# Architecture & Motivation: Client Architecture

The success and resilience of a decentralized protocol depend entirely on its accessibility. If running a node requires a degree in systems administration or a dedicated cloud server, the network will inevitably centralize around a few hobbyists and corporations.

Kinetic solves this accessibility problem by providing two distinct client models: The **Tauri Desktop Client** for running robust full nodes, and **WebAssembly (Wasm)** compilation for zero-trust browser light clients.

## The Tauri Desktop App (Full Node)

To provide a seamless, non-technical "one-click install" for Windows, macOS, and Linux users, Kinetic bundles the core daemon, the UI dashboard, and the local split-DNS resolver into a single **Tauri Desktop Application** (`kinetic-client/desktop/src-tauri`).

### Why Tauri instead of Electron?
Historically, most cross-platform desktop apps (like Slack, Discord, or early crypto wallets) were built using Electron. Electron works by bundling an entire Chromium web browser and a complete Node.js runtime into every application. This results in massive binary sizes (often 200MB+) and heavy idle RAM consumption. 

A Kinetic node is fundamentally different from a chat app. It is expected to run quietly in the background 24/7 to maintain the DHT routing table, seed data, and provide local DNS resolution for the OS. If Kinetic used Electron, it would continuously drain laptop batteries and hog system memory just sitting idle.

Tauri solves this architectural dilemma:
1. **Rust Backend:** The heavy cryptographic lifting—maintaining the P2P DHT, performing the 16 MiB Argon2id PoW checks, verifying ML-DSA signatures, and running the UDP DNS server—is compiled to highly optimized, memory-safe native Rust.
2. **OS Webviews:** Instead of shipping a bundled Chromium binary, Tauri intelligently hooks into the operating system's native webview engine (Edge WebView2 on Windows, WebKit on macOS, WebKitGTK on Linux) to render the UI. 

This hybrid approach results in a tiny binary footprint (often under 20MB) and near-zero resource consumption when the UI is closed or minimized to the system tray, making it perfectly suited for an always-on decentralized node.

### IPC Isolation and the Security Boundary
In Tauri, the React/TypeScript frontend runs inside the restricted webview sandbox, while the Kinetic daemon and core logic run in the native Rust backend process. They communicate exclusively via strongly-typed Inter-Process Communication (IPC) messages. 

This architecture provides a massive security boundary. If the React frontend were somehow compromised via a complex cross-site scripting (XSS) attack or a malicious NPM dependency, the attacker would be trapped inside the OS webview sandbox. They cannot use `fs.readFileSync` to steal the user's `identity.key` or maliciously modify the VDF `reveal.json` proofs, because the webview has absolutely no access to the local filesystem. All sensitive cryptographic material remains strictly guarded by the Rust backend, which validates every incoming IPC command before executing it.

## WebAssembly (Wasm) Light Clients

While the Tauri desktop app acts as a full participant (Full Node) on the DHT, third-party web developers need a way to verify Kinetic identities (`did:kin`) and names natively inside web browsers without asking their users to install a desktop app.

To support this ubiquitous web integration, the `kinetic-kid` (identity protocol) and `kinetic-core` crates are specifically designed to compile to `wasm32-unknown-unknown` **WebAssembly (Wasm)**.

### The Light-Client Trust Model

In the Web3 ecosystem, a "light client" often just refers to a Javascript library that sends an API request to a centralized RPC provider (like Infura or Alchemy) and blindly trusts the JSON response. This completely breaks the security model, devolving the system back into centralized Web2.

Kinetic enforces a **Zero-Trust Wasm Architecture**. 
With Kinetic Wasm clients, the browser application might ask a random public DHT gateway for the records of `alice.kin`. Crucially, the browser does not trust the gateway. The gateway must return the raw data payload *alongside all accompanying cryptographic VDF proofs and ML-DSA-65 signatures*. 

The Wasm module running locally inside the user's browser takes over. It executes the VDF verification algorithms and the ML-DSA signature math directly on the client's CPU. If the gateway lies, attempts to censor, or provides forged data, the mathematical verification fails. The Wasm client immediately rejects the payload. 

This elegant architecture allows browser-based applications to maintain cryptographically guaranteed zero-trust security without needing to sync the entire massive DHT, ensuring Kinetic's identity layer remains uncompromisingly secure even on lightweight devices.
