# Technical Paper III: Networking & Execution Environment

**Author:** Saif Mukhtar
**Date:** July 2026
**Version:** 1.0.0

## Abstract
While the cryptographic mathematics define the consensus laws of the Kinetic Protocol, the local client environment enforces them. To function as practical public infrastructure, Kinetic must bypass the legacy Domain Name System (DNS) seamlessly, without breaking standard internet traffic or requiring complex user configurations. This paper formalizes the architecture of the Kinetic Daemon, documenting its Sovereign Split-DNS loopback interception, dynamic Certificate Authority (CA) generation for HTTPS, and trust-minimized delegated computation routing over the Nostr protocol.

---

## 1. Introduction
A decentralized namespace has no utility if it cannot be natively accessed by standard internet browsers. Historically, projects attempting to build alternate domain roots require specialized browser extensions or custom DNS configurations that break legacy web access. The Kinetic Daemon solves this integration problem at the operating system level, acting as a transparent routing bridge between Web2 software and the decentralized Kademlia Distributed Hash Table (DHT).

## 2. Sovereign Split-DNS via Loopback Interception

The primary engineering challenge is integrating natively into user applications without central Top-Level Domain (TLD) authorities. Kinetic solves this via a strictly deterministic Split-DNS loopback architecture.

When the Kinetic daemon initializes, it binds a local DNS proxy to the operating system's loopback interface (e.g., `127.0.0.1:53`). The OS networking stack prioritizes this proxy for all outbound DNS queries.

The daemon enforces the following Split-DNS policy:
* **Legacy Pass-Through:** If an application requests a standard TLD (`github.com`), the daemon instantly forwards the raw byte buffer to an upstream resolver (e.g., `1.1.1.1`). This incurs zero latency overhead for normal internet use.
* **Sovereign Interception:** If a query targets a `.kin` domain, the daemon traps the request, queries the Kinetic DHT, validates the VDF proofs mathematically, and synthesizes a standard DNS `A` record containing the decentralized IP. The browser then natively resolves the `.kin` endpoint.

## 3. Dynamic CA Generation & HTTPS Proxying

A critical hurdle in decentralized routing is TLS/SSL. Modern browsers will refuse to load websites over HTTPS without a certificate signed by a globally trusted Certificate Authority (CA). Relying on central CAs fundamentally breaks sovereign peer-to-peer networks.

To circumvent this, the `kinetic-daemon` employs a local HTTPS interceptor (`proxy.rs` and `ca.rs`):
1. **Root CA Generation:** Upon installation, the daemon generates a unique, local Root Certificate Authority and injects it into the host OS trust store.
2. **On-the-Fly Leaf Certificates:** When a user navigates to `https://saif.kin`, the daemon's proxy intercepts the connection, dynamically mints a valid leaf certificate for `saif.kin` signed by the local Root CA, and serves it to the browser.
3. **Transparent Forwarding:** The proxy then securely forwards the traffic to the actual peer-to-peer endpoint defined in the domain's Capability Manifest.

This guarantees that `.kin` domains display the secure TLS padlock icon in standard browsers, achieving parity with legacy Web2 infrastructure.

## 4. Delegated Compute via Nostr

Because claiming a name requires massive VDF computation (often burning hours of CPU time), mobile devices with battery constraints are practically excluded from the registration process.

To achieve network accessibility, Kinetic implements **Delegated Compute** utilizing the Nostr protocol [1]. A user on a mobile device can construct a signed registration commitment, encrypt it using the Nostr NIP-04 (Encrypted Direct Message) specification, and broadcast it to a specific public key belonging to their desktop Kinetic daemon (or a paid compute-provider). 

The desktop daemon receives the encrypted request, executes the grueling VDF using high-performance hardware, and automatically publishes the resulting reveal tuple to the DHT. Because the commitment strictly binds the payload to the mobile user's public key, the delegator cannot steal the name, achieving a trust-minimized offload of computational friction.

## 5. Host Architecture & Epoch-Bound Identity

A unique element of the Kinetic Networking Environment is the `kinetic-host` node. A Host is a `.kin` domain owner that publicly serves content or services through the network. It acts simultaneously as a full peer-to-peer node and a reverse proxy, forwarding incoming P2P requests to local HTTP backend servers.

To prevent targeted Denial of Service (DoS) attacks and network-layer tracking, the `kinetic-host` deploys a highly advanced dual-identity system utilizing S/Kademlia [2] mechanics:

1. **Static Host Identity:** A permanent Ed25519 keypair uniquely identifies the host across time. This key is strictly used to cryptographically sign `HostRoutingRecords` that are published to the global DHT.
2. **Epoch-Bound PoW Identity:** On the libp2p transport layer, the host utilizes a completely ephemeral identity. The host continuously mines a new Proof-of-Work network keypair specifically bound to the current `drand` pulse.

When the `drand` epoch advances, the host automatically aborts its old network loop, sheds its ephemeral identity, and hot-swaps to a newly mined identity with zero downtime. Because clients resolve the target using the signed `HostRoutingRecords` stored in the DHT, legitimate traffic always locates the current ephemeral peer ID, while attackers attempting to DoS the host's direct libp2p transport layer are instantly dropped at every epoch tick.

## 6. Conclusion
By utilizing OS-level DNS loopbacks, dynamic Certificate Authorities, and Epoch-Bound transport identities, the Kinetic Networking Environment bridges the gap between cryptographic sovereignty and mainstream usability—achieving attack-resiliency without requiring modifications to standard web browsers.

---

## References

[1] fiatjaf. (2020). *NIP-04: Encrypted Direct Message.* Nostr Implementation Possibilities. Retrieved from https://github.com/nostr-protocol/nips

[2] Baumgart, I., & Mies, S. (2007). *S/Kademlia: A practicable approach towards secure key-based routing.* In 2007 International Conference on Parallel and Distributed Systems (pp. 1-8). IEEE.
