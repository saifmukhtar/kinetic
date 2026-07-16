# Technical Paper III: Networking & Execution Environment

**Author:** Saif Mukhtar
**Date:** July 2026
**Version:** 2.0.0

## Abstract

While the cryptographic mathematics define the consensus laws of the Kinetic Protocol, the local client environment enforces them. To function as practical public infrastructure, Kinetic must bypass the legacy Domain Name System (DNS) seamlessly, without breaking standard internet traffic or requiring complex user configurations. This paper formalizes the architecture of the Kinetic Daemon, documenting its Sovereign Split-DNS loopback interception, dynamic Certificate Authority (CA) generation for HTTPS, Epoch-Bound transport identity, and the Host Architecture that enables decentralized reverse proxying.

All networking components are fully fork-aware. The intercepted TLD is read from `network.json` at compile time, so a fork deploying `.uni` will automatically intercept `.uni` queries — not `.kin` — with zero code changes required.

---

## 1. Introduction

A decentralized namespace has no utility if it cannot be natively accessed by standard internet browsers. Historically, projects attempting to build alternate domain roots required specialized browser extensions or custom DNS configurations that broke legacy web access. The Kinetic Daemon solves this integration problem at the operating system level, acting as a transparent routing bridge between Web2 software and the decentralized Kademlia Distributed Hash Table (DHT).

---

## 2. Sovereign Split-DNS via Loopback Interception

The primary engineering challenge is integrating natively into user applications without central Top-Level Domain (TLD) authorities. Kinetic solves this via a strictly deterministic Split-DNS loopback architecture.

When the Kinetic Daemon initializes, it binds a local DNS proxy to the operating system's loopback interface (`127.0.0.1:53`). The OS networking stack is configured to prioritize this proxy for all outbound DNS queries — using `systemd-resolved` on Linux, `/etc/resolver` on macOS, and NRPT (Name Resolution Policy Table) on Windows.

The daemon enforces the following Split-DNS policy:

- **Legacy Pass-Through:** If an application requests a standard TLD (e.g., `github.com`), the daemon instantly forwards the raw byte buffer to the upstream resolver (`1.1.1.1` or `8.8.8.8`). This incurs zero latency overhead for normal internet use.
- **Sovereign Interception:** If a query targets the network's configured TLD (e.g., `.kin` on the canonical network), the daemon traps the request, queries the Kinetic DHT, validates the VDF proofs and Ed25519 signatures locally, and synthesizes a standard DNS `A` record containing the decentralized IP. The browser natively resolves the endpoint with no awareness that a DHT was involved.

**Fork Note:** A university fork configured with TLD `.uni` will intercept `.uni` queries and pass everything else through identically. The TLD is compiled from `network.json` — there is no TLD-specific logic in the daemon binary.

---

## 3. Dynamic CA Generation & HTTPS Proxying

A critical hurdle in decentralized routing is TLS/SSL. Modern browsers refuse to load websites over HTTPS without a certificate signed by a globally trusted Certificate Authority (CA). Relying on central CAs fundamentally breaks sovereign peer-to-peer networks.

To circumvent this, the `kinetic-daemon` employs a local HTTPS interceptor (`proxy.rs`, `ca.rs`):

1. **Root CA Generation:** Upon installation, the daemon generates a unique, local Root Certificate Authority and injects it into the host OS trust store using the PAC (Proxy Auto-Config) system (`kinetic-daemon/src/pac/`).
2. **On-the-Fly Leaf Certificates:** When a user navigates to `https://example.kin`, the daemon's proxy intercepts the TLS handshake, dynamically mints a valid leaf certificate for `example.kin` signed by the local Root CA, and serves it to the browser transparently.
3. **Transparent Forwarding:** The proxy then securely forwards the traffic to the actual peer-to-peer endpoint defined in the domain's Capability Manifest.

This guarantees that `.kin` domains (or any fork's TLD) display the secure TLS padlock in standard browsers, achieving functional parity with legacy Web2 infrastructure without requiring any browser modification.

---

## 4. Host Architecture & Epoch-Bound Transport Identity

A unique element of the Kinetic Networking Environment is the `kinetic-host` node. A Host is a domain owner that publicly serves content or services through the network. It acts simultaneously as a full peer-to-peer node and a reverse proxy, forwarding incoming P2P requests to local HTTP backend servers.

To prevent targeted Denial of Service (DoS) attacks and network-layer tracking, `kinetic-host` deploys a dual-identity system utilizing S/Kademlia [1] mechanics:

### 4.1 Static Host Identity

A permanent Ed25519 keypair uniquely identifies the host across time. This key is strictly used to cryptographically sign `HostRoutingRecords` that are published to the global DHT. The signed record tells clients: *"This is the current ephemeral peer ID to connect to for `example.kin`."* This key never touches the libp2p transport layer directly.

### 4.2 Epoch-Bound PoW Transport Identity

On the libp2p transport layer, the host uses a completely ephemeral identity. The host continuously mines a new Proof-of-Work network keypair bound specifically to the current `drand` Quicknet pulse. This PoW keypair is used for all raw TCP/UDP connections from peers.

When the `drand` epoch advances (every 3 seconds), the host:
1. Aborts the old network event loop
2. Sheds the old ephemeral peer ID entirely
3. Mines a new PoW keypair for the new epoch
4. Hot-swaps to the new identity with zero downtime
5. Publishes the updated `HostRoutingRecord` to the DHT

Because legitimate clients resolve the target using the signed `HostRoutingRecord` from the DHT, they always locate the current ephemeral peer ID. Attackers attempting to DoS the host's direct libp2p transport layer are invalidated at every epoch tick — their connection attempt targets a peer ID that no longer exists.

---

## 5. Delegated Compute (Planned — Phase 2)

Because claiming a name requires massive VDF computation (potentially hours of CPU time), mobile devices with battery constraints are practically excluded from direct registration.

The planned solution is **Delegated Compute** utilizing the Nostr protocol [2]. A user on a mobile device constructs a signed registration commitment, encrypts it using Nostr NIP-04 (Encrypted Direct Message), and broadcasts it to a specific public key belonging to their desktop Kinetic daemon or a paid compute provider.

The desktop daemon receives the encrypted request, executes the VDF using high-performance hardware, and publishes the resulting reveal tuple to the DHT. Because the commitment strictly binds the payload to the mobile user's public key, the delegator cannot steal the name.

> **Current Status:** The mobile commitment architecture and key delegation structure are implemented. The Nostr transport integration is planned for Phase 2. In the current version, mobile delegation is achieved via a direct local network connection between the mobile client and the desktop daemon.

---

## 6. P2P Network Stack

The networking layer is implemented in the `kinetic-network` crate using:

- **rust-libp2p:** Core P2P framework providing Kademlia DHT, TCP/QUIC transports, and peer identity.
- **Kademlia DHT:** Modified to enforce strict payload validation before storage (`kinetic-network/src/store/verification.rs`). Invalid VDF proofs are rejected at the gossip layer — poisoned records never enter the DHT.
- **Bootstrap Nodes:** Defined in `network.json` under `bootstrap_nodes`. Fork operators replace these with their own infrastructure nodes.

The `kinetic-node` crate provides a headless, cloud-optimized infrastructure node specifically designed for running as a stable DHT backbone peer, separate from the end-user `kinetic-daemon`.

---

## 7. Conclusion

By utilizing OS-level DNS loopbacks, dynamic Certificate Authorities, and Epoch-Bound transport identities, the Kinetic Networking Environment bridges the gap between cryptographic sovereignty and mainstream usability — achieving attack-resiliency without requiring any modifications to standard web browsers. The entire networking stack is TLD-agnostic and fork-ready by design.

---

## References

[1] Baumgart, I., & Mies, S. (2007). *S/Kademlia: A practicable approach towards secure key-based routing.* In 2007 International Conference on Parallel and Distributed Systems (pp. 1-8). IEEE.

[2] fiatjaf. (2020). *NIP-04: Encrypted Direct Message.* Nostr Implementation Possibilities. Retrieved from https://github.com/nostr-protocol/nips

[3] Maymounkov, P., & Mazières, D. (2002). *Kademlia: A peer-to-peer information system based on the XOR metric.* IPTPS '02.
