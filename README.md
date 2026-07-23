<div align="center">
  <picture>
    <img alt="Kinetic: Decentralized, Zero-Cost, VDF-Secured Namespace Engine" src="./assets/readme/hero.svg" width="100%">
  </picture>
  <p>
    <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0"/></a>
    <a href="https://kinetic.saifmukhtar.dev"><img src="https://img.shields.io/badge/docs-kinetic.saifmukhtar.dev-green.svg" alt="Documentation"/></a>
    <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-1.80%2B-orange.svg" alt="Rust"/></a>
    <a href="https://github.com/saifmukhtar/kinetic"><img src="https://img.shields.io/github/stars/saifmukhtar/kinetic?style=social" alt="GitHub stars"/></a>
  </p>
  <p>
    <a href="https://www.ietf.org/archive/id/draft-mukhtar-kinetic-network-00.html"><img src="https://img.shields.io/badge/IETF_Draft-Kinetic_Network-blue" alt="IETF Draft Network"/></a>
    <a href="https://www.ietf.org/archive/id/draft-mukhtar-kinetic-identity-00.html"><img src="https://img.shields.io/badge/IETF_Draft-Kinetic_Identity-purple" alt="IETF Draft Identity"/></a>
  </p>
</div>

---

## What is Kinetic?

Kinetic is a **decentralized naming and identity engine** written in Rust. It solves the domain naming problem without using centralized authorities (like ICANN) and without blockchains or crypto tokens.

Instead of paying money for a name, you pay with **time**. By solving a mathematical puzzle called a Verifiable Delay Function (VDF), you prove you spent un-parallelizable computation time to register a name. 
- **Zero Cost:** Registering a name costs exactly $0.
- **Squatter-Resistant:** A 1-character name takes ~100 years of CPU time. A 6-character name takes ~12 hours. Mass squatting is physically impossible.
- **True Ownership:** Your name is bound to a post-quantum cryptographic identity (ML-DSA-65) that only you control.

You can use Kinetic in two ways: **Join the global `.kin` network**, or **Fork the engine** to deploy a sovereign network for your organization.

---

## 🏗️ How It Works (High-Level)

Kinetic integrates directly into your operating system. It acts as a lightweight, transparent DNS router:

<div align="center">
  <picture>
    <img alt="Kinetic Transparent Split-DNS Architecture" src="./assets/readme/architecture.svg" width="100%">
  </picture>
</div>

When you type a `.kin` address into your browser, the Kinetic Daemon intercepts it, verifies the cryptographic proof on the P2P network, and routes you to the content securely. All standard internet traffic passes through untouched.

---

## 🌐 Use the `.kin` Network (Quick Start)

The `.kin` network is the public, permissionless deployment of the Kinetic engine. 

### 1. Install the CLI

**Linux & macOS:**
```bash
curl -sL https://kinetic.saifmukhtar.dev/install.sh | bash
```

**Windows (PowerShell as Admin):**
```powershell
Invoke-WebRequest -Uri "https://kinetic.saifmukhtar.dev/install.ps1" -OutFile "install.ps1"; .\install.ps1
```

### 2. Register Your First Name

Once the daemon is running, you can register a name right from your terminal:

```bash
# Register a name (grinds a VDF on your CPU)
kinetic register myname.kin

# Once complete, publish it to the global network
kinetic publish myname.kin
```

You can now use `myname.kin` to host a website, build a decentralized app, or establish your digital identity!

> **Want the Desktop App?** Check out the graphical client at [saifmukhtar/kinetic-client](https://github.com/saifmukhtar/kinetic-client).

---

## 🍴 Fork Your Own Network

Kinetic is designed to be forked. If you are a university, enterprise, or community, you don't have to share the `.kin` namespace. You can deploy your own sovereign network (e.g., `.uni`, `.corp`) in minutes.

Using the built-in `kinetic-forge` wizard, you can generate a custom network configuration that gets compiled directly into your binaries. You set your own TLD, adjust the VDF difficulty to your liking, and retain full cryptographic governance over your network's future. 

Because you control the governance keys on a fork, automated squatters face absolute risk: you can reset the network at any time.

→ **[Read the Forking Guide](https://kinetic.saifmukhtar.dev/forking.html) to learn how to deploy your own Kinetic engine.**

---

## 👩‍💻 Building from Source

Kinetic requires Rust 1.80+ and a few C++ dependencies for the VDF engine.

**1. Install Prerequisites:**
```bash
# Ubuntu / Debian
sudo apt install build-essential cmake libgmp-dev

# macOS
brew install cmake gmp
```

**2. Clone and Build:**
```bash
git clone https://github.com/saifmukhtar/kinetic.git
cd kinetic

# ALWAYS build in release mode. The VDF math is unplayably slow in debug mode.
cargo build --release --workspace
```

---

## 📚 Documentation & Whitepapers

Dive deeper into the math, security, and architecture of Kinetic:

- **[Full Documentation](https://kinetic.saifmukhtar.dev)**
- **[Vision Overview](./whitepaper/kinetic-vision.md)**
- **[Consensus & Proof of Patience](./whitepaper/kinetic-consensus.md)**
- **[Identity Architecture (KID)](./whitepaper/kinetic-identity.md)**
- **[Network & Execution](./whitepaper/kinetic-network.md)**
- **[Security & Mitigation](./whitepaper/kinetic-security.md)**

---

## 🤝 Contributing & Security

Kinetic is built by the community. We prioritize extreme technical rigor and objective engineering. 

- **[CONTRIBUTING.md](./.github/CONTRIBUTING.md):** Learn how to submit PRs, run the 50-node simulation sandbox, and adhere to our strict inline documentation standards.
- **[THREAT_MODEL.md](./.github/THREAT_MODEL.md):** Read our comprehensive adversarial analysis, detailing what we protect against and our trust assumptions.
- **[GOVERNANCE.md](./.github/GOVERNANCE.md):** Understand the Bicameral Rule Book, the 69% council supermajority, and how to become a core maintainer.
- **[SECURITY.md](./.github/SECURITY.md):** Instructions for disclosing vulnerabilities securely.

---

## 🙏 Built On

Kinetic stands on the shoulders of incredible open-source infrastructure:

- **[rust-libp2p](https://github.com/libp2p/rust-libp2p):** The core P2P networking stack. Kinetic implements a custom `kad::store::RecordStore` (`KineticRecordStore`) for the Kademlia DHT to enforce strict VDF proof validation and signature checks before any payload is stored. Also utilizes Gossipsub, Noise, Yamux, and DCUtR for NAT traversal.
- **[chiavdf (Chia Network)](https://github.com/Chia-Network/chiavdf):** C++ VDF engine utilizing Class Groups of Imaginary Quadratic Fields.
- **[drand Quicknet](https://drand.love/):** Distributed randomness beacon for ungameable challenges.
- **[sled](https://github.com/spacejam/sled):** The pure-Rust embedded B-tree database.
- **[hickory-dns](https://github.com/hickory-dns/hickory-dns):** Powering the Sovereign Split-DNS interception layer.
- **[axum](https://github.com/tokio-rs/axum):** The high-performance async REST API engine.
- **[rustls](https://github.com/rustls/rustls) & [rcgen](https://github.com/rustls/rcgen):** For dynamic, on-the-fly Certificate Authority generation and HTTPS proxying.
- **[ml-dsa](https://github.com/RustCrypto/signatures/tree/master/ml-dsa):** Providing FIPS 204 post-quantum cryptographic identities.

---

<div align="center">
  <p><strong>Codebase License:</strong> <a href="LICENSE">Apache 2.0</a> | <strong>Whitepapers:</strong> <a href="./docs/LICENSE">CC BY 4.0</a></p>
  <p><em>Created by <a href="https://saifmukhtar.dev">Saif Mukhtar</a></em></p>
</div>
