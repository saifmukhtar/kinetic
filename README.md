# ⚡ The Kinetic Protocol

*A stateless, Sybil-resistant naming system secured purely by math and time.*

## 🩸 The Pain of Digital Landlordism

Have you ever tried to register a domain name for a side project, only to find out a squatter has parked it and is demanding $5,000? Or worse, you finally secure a decent domain, but are forced to pay a centralized registrar $15 to $50 every single year just to keep it alive? 

Why are we paying endless rent for mathematical space?

Current decentralized identity and naming architectures (like ENS or Handshake) inevitably replicate the rent-seeking vulnerabilities of Web2 registry systems, creating an artificial economy of **digital landlordism**. To secure human-readable namespaces against Sybil attacks and squatting, existing protocols rely on:
1. **Continuous capital allocation** (perpetual renewal fees) which prices out independent developers and favors wealthy speculators.
2. **Intrusive identity verification** (Proof of Personhood) which introduces severe onboarding friction and privacy concerns.

**Kinetic replaces monetary cost with sequential computational friction.** It establishes a self-cleaning namespace where mass-scale automated squatting becomes computationally and energetically ruinous, while remaining completely friction-free and zero-cost for a legitimate, solitary developer.

---

## 🏗️ How It Works (The Split-DNS Daemon)

To achieve native `.kin` resolution without relying on centralized top-level domain (TLD) authorities, Kinetic utilizes a lightweight background daemon that binds a local DNS proxy to the operating system's loopback interface.

Because the browser speaks standard DNS and the `kinetic-dns` proxy speaks standard DNS, the browser has absolutely no idea that it just resolved a domain via a hostile, mathematically-secured Kademlia swarm. The integration is seamless.

```mermaid
graph LR
    subgraph User OS
        App[Browser / Application]
        Daemon((Kinetic Daemon<br/>127.0.0.2:53))
        App -->|DNS Query| Daemon
    end

    subgraph Split-DNS Router
        Daemon -->|Ends in .kin| Kin{Intercept}
        Daemon -->|Other TLDs| Pass{Pass-Through}
    end

    subgraph External Networks
        Kin -->|VDF/DHT Math| DHT[(Kademlia DHT)]
        Pass -->|Standard UDP/TCP| Upstream[Upstream Resolver<br/>1.1.1.1 / 8.8.8.8]
        Upstream --> ICANN((ICANN Root Zone))
    end
    
    style Daemon fill:#005A9C,stroke:#000,stroke-width:2px,color:#fff
    style Kin fill:#9400D3,stroke:#000,stroke-width:2px,color:#fff
    style Pass fill:#228B22,stroke:#000,stroke-width:2px,color:#fff
```

## 📖 Official Documentation
Everything you need to know about Kinetic, the VDF math, and how to build on the network is available at:
**[https://saifmukhtar.github.io/kinetic/](https://saifmukhtar.github.io/kinetic/)**

---

## 🚀 Quick Setup (macOS & Linux)

You can install the compiled Kinetic Daemon and integrate it into your system DNS with a single command. The installer safely integrates with your OS (`systemd-resolved` on Linux, `/etc/resolver` on macOS) without breaking your standard internet traffic.

```bash
# 1. Install the Daemon and CLI
curl -sL https://raw.githubusercontent.com/saifmukhtar/kinetic/main/install.sh | bash

# 2. (Linux) Check that the background service is running
sudo systemctl status kinetic-daemon

# 2. (macOS) Check that the background service is running
sudo launchctl list | grep kinetic
```

## 🪟 Quick Setup (Windows)

Open **PowerShell as Administrator** and run:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/saifmukhtar/kinetic/main/install.ps1" -OutFile "install.ps1"; .\install.ps1
```

The Windows installer uses native **NRPT (Name Resolution Policy Table)** to magically route strictly `.kin` domains without altering your primary Wi-Fi/Ethernet DNS settings!

---

## ⛏️ Mining Your Name (The CLI)

Because Kinetic binds ownership of a name to the cryptographic identity (Ed25519 keypair) of the machine that mines it, you should mine names directly from your personal computer.

Once your daemon is running, you can use the `kinetic-cli` to interact with the Kademlia swarm and secure your name. 

### 1. Registering a Name
To register a `.kin` domain and point it to an IP address, use the `register` command. This will instantly queue the Kademlia payload and trigger your daemon's background Heartbeat loop to cryptographically protect the name.
```bash
kinetic-cli register myname.kin 192.168.1.100
```

### 2. Hibernating a Name
If you are turning off your computer for a long time (vacation) and cannot send Heartbeats, you can compute a massive 48-hour Verifiable Delay Function (VDF) to "Hibernate" your name. This proves extreme computational dedication upfront, exempting you from Heartbeats for 1 year.
```bash
kinetic-cli hibernate myname.kin
```

### 3. Delegating to a Watchtower
If you want a dedicated cloud server to maintain your name while your laptop is offline, you can pre-sign a chain of future heartbeats and hand them to a Watchtower daemon. The Watchtower can publish your heartbeats but cannot steal your name!
```bash
kinetic-cli generate-watchtower myname.kin 30  # Delegate for 30 days
```

---

## 📚 The Whitepaper

The complete architectural theory, mechanics, and cryptographic proofs are documented in the **[Kinetic Whitepaper](https://saifmukhtar.github.io/kinetic/)**. 

The whitepaper details our solutions to critical decentralized naming vulnerabilities, including:
*   **The Front-running Fix:** Clockless, sequential VDF linking anchored to a `drand` beacon.
*   **The Dictionary Squatting Fix:** Dynamic difficulty scaling via Verifiable Delay Functions.
*   **The Vacation Problem Fix:** A Hybrid Lease System combining Grace-Period Escalation and Hibernation VDFs.
*   **The Spam Fix:** Competitive Gossip and connection-level Hashcash Proof-of-Work.

## 📄 License

This project operates under a dual-license structure:
* **Codebase:** Licensed under the **[Apache License 2.0](LICENSE)**.
* **Whitepaper & Documentation:** Licensed under **[CC BY 4.0](./whitepaper/LICENSE)**.
