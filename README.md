<div align="center">
  <img src=".github/assets/kinetic-banner.png" alt="Kinetic Protocol Banner" width="100%" />
  <br />
  <h1>Kinetic Engine</h1>
  <p><strong>A Sovereign, Post-Quantum Decentralized Naming and Routing Protocol</strong></p>
  <a href="https://kinetic.saifmukhtar.dev">Documentation</a> &nbsp;&bull;&nbsp; <a href="#-architecture--whitepapers">Whitepapers</a> &nbsp;&bull;&nbsp; <a href="#-deploy-your-own-sovereign-network">kinetic-forge</a>
</div>

---

## ⚡ Overview

Kinetic is a highly modular, decentralized engine designed to power cryptographically secure, censorship-resistant namespaces without blockchains, miners, or central authorities. 

It provides the foundational protocol stack required to construct autonomous networks. While Kinetic currently powers the global `.kin` public commons, the engine itself is completely namespace-agnostic. It can be deployed by universities, enterprises, or private communities to forge completely isolated, mathematically secure routing zones (e.g., `.corp`, `.uni`, or `.mesh`).

By leveraging **Class Group Verifiable Delay Functions (VDFs)** for anti-squatting, **ML-DSA-65** for post-quantum identity, and a **Kademlia DHT** for sovereign peer-to-peer routing, the Kinetic Engine redefines decentralized infrastructure.

---

## 🏗️ Core Engine Capabilities

Kinetic is built using strict Clean Architecture principles, ensuring that underlying subsystems can be independently scaled, audited, or hot-swapped.

### ⏳ Time-Based Consensus (Proof of Patience)
Kinetic discards traditional Proof-of-Work (PoW) and Proof-of-Stake (PoS). Instead, it secures namespaces using **Verifiable Delay Functions (VDFs)** and the **drand** randomness beacon. Name acquisition requires un-parallelizable cryptographic time (CPU hours/days), mathematically ensuring fairness and eliminating domain squatting without requiring a global ledger.

### 🔐 Post-Quantum Identity (KID)
Every node and routing zone is anchored to a **Kinetic Identity Document (KID)**. Kinetic proactively defends against harvest-now-decrypt-later attacks by standardizing on **FIPS 204 ML-DSA-65** post-quantum digital signatures for all zone payload validations and peer authentication.

### 💾 Pluggable Storage Architecture
The engine features a fully abstracted storage layer (`kinetic-storage`). Decentralized network states and local configurations are managed through clean trait boundaries, allowing the underlying database (currently leveraging `redb` for safe, high-concurrency embedded storage) to be seamlessly swapped based on deployment scale.

### 🌐 Native Split-DNS Interception
The `kinetic-daemon` acts as a transparent Split-DNS gateway. When operating locally on port 53, it intercepts queries for sovereign namespaces (like `.kin`), resolves the payloads via the P2P DHT, and transparently passes standard internet traffic (like `github.com`) to upstream OS resolvers without latency overhead.

### 🖥️ Headless REST API & TUI CLI
The Kinetic daemon exposes a comprehensive, OpenAPI-compliant REST API (`/api/v1/micro` and `/macro`) that powers Web2 bridges, localized dashboards, and external integrations. It is paired with `kinetic-cli`, a modern, interactive terminal interface featuring real-time VDF progress tracking and structured network telemetry.

---

## 🍴 Deploy Your Own Sovereign Network

Kinetic is designed from the ground up to be engine-swappable and engine-forkable. Any organization can deploy their own independent, cryptographically isolated namespace in minutes using the `kinetic-forge` module.

```bash
cargo run --release --bin kinetic-forge
```

1. **Configure Network Constants:** Define custom Top-Level Domains (NSPs), bootstrap nodes, and target VDF delay constraints in `network.json`.
2. **Compile Engine:** Constants are injected directly into the binary suite via `build.rs` for maximum performance and zero configuration drift.
3. **Establish Governance:** Maintain sovereign governance keys with emergency timelocks and 69% maintenance council ratifications.

📖 **[Read the Complete Engine Forking & Custom Network Guide](https://kinetic.saifmukhtar.dev/vdf-calibration.html)**

---

## 💻 Building the Engine from Source

Kinetic requires **Rust 1.80+** and C++ build tools for the `chiavdf` FFI subsystem.

### 📦 Prerequisites

**Ubuntu / Debian:**
```bash
sudo apt update && sudo apt install -y build-essential cmake libgmp-dev
```

**macOS (Homebrew):**
```bash
brew install cmake gmp
```

### 🔨 Compilation

```bash
git clone https://github.com/saifmukhtar/kinetic.git
cd kinetic
cargo build --release --workspace
```

> ⚠️ **CRITICAL:** Always compile with `--release`. Debug builds lack compiler SIMD/LTO optimizations, making cryptographic VDF squarings unusably slow.

---

## 📚 Architecture & Whitepapers

Explore the mathematical proofs, RFC drafts, and security models powering the Kinetic Engine:

### 📜 Official Whitepapers (`whitepaper/`)
- 📄 **[1. Vision & Executive Summary](./whitepaper/kinetic-vision.md):** The case for sovereign time-secured namespaces.
- ⚡ **[2. Consensus & Proof of Patience](./whitepaper/kinetic-consensus.md):** Name Difficulty Curve (NDC) mathematical proofs.
- 🆔 **[3. Decentralized Identity Architecture](./whitepaper/kinetic-identity.md):** Post-quantum ML-DSA-65 identity documents.
- 🌐 **[4. Network & Execution Spec](./whitepaper/kinetic-network.md):** libp2p Kademlia DHT, gossip subtopics, and Split-DNS.
- 🛡️ **[5. Security & Threat Mitigation](./whitepaper/kinetic-security.md):** Formal resistance to Sybil and Eclipse attacks.
- 🏛️ **[6. Governance Engine](./whitepaper/kinetic-governance.md):** Council multisig rules and timelock emergency resets.
- 🔨 **[7. Kinetic Engine Forking (`kinetic-forge`)](./whitepaper/kinetic-forge.md):** Custom NSP network deployment guide.

### 📜 IETF Internet-Draft Specifications
- 📑 **[draft-mukhtar-kinetic-network-00](https://www.ietf.org/archive/id/draft-mukhtar-kinetic-network-00.html):** The Kinetic Network Protocol Specification.
- 📑 **[draft-mukhtar-kinetic-identity-00](https://www.ietf.org/archive/id/draft-mukhtar-kinetic-identity-00.html):** The Kinetic Identity (KID) Specification.

---

## 🛠️ Open-Source Foundation

The Kinetic Engine is built upon world-class open-source infrastructure:

- 🦀 **[rust-libp2p](https://github.com/libp2p/rust-libp2p):** Peer-to-peer networking, Kademlia DHT, and NAT traversal.
- 🧮 **[chiavdf](https://github.com/Chia-Network/chiavdf):** High-speed Class Group VDF repeated squarings engine.
- 🎲 **[drand](https://drand.love/):** Ungameable threshold randomness beacon.
- ⚡ **[hickory-dns](https://github.com/hickory-dns/hickory-dns):** Sovereign Split-DNS server interception framework.
- 🔑 **[ml-dsa](https://github.com/RustCrypto/signatures/tree/master/ml-dsa):** FIPS 204 post-quantum digital signature algorithms.
- 💾 **[redb](https://github.com/cberner/redb):** Embedded pure-Rust safe database.
- 🚀 **[axum](https://github.com/tokio-rs/axum):** Modern async web framework powering the REST API daemon.

---

<div align="center">
  <p><strong>Code License:</strong> <a href="LICENSE">Apache License 2.0</a> &nbsp;|&nbsp; <strong>Documentation & Specs:</strong> <a href="./docs/LICENSE">Creative Commons Attribution 4.0 International (CC BY 4.0)</a></p>
  <p><em>Engineered by <a href="https://saifmukhtar.dev">Saif Mukhtar</a></em> &nbsp;•&nbsp; 🌐 <a href="https://kinetic.saifmukhtar.dev">kinetic.saifmukhtar.dev</a></p>
</div>
