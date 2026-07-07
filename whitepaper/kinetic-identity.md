# Technical Paper II: The Identity Architecture (KID)

**Author:** Saif Mukhtar
**Date:** July 2026
**Version:** 1.0.0

## Abstract
Traditional decentralized naming systems attempt to replicate legacy DNS logic by directly mapping a human-readable identifier to a network location (IP address). The Kinetic Protocol introduces an alternative paradigm: an Identity-Centric Service Discovery Network. This paper formalizes the Kinetic Identity Document (KID) architecture, establishing a four-layer progression that securely separates Human Discovery, Identity, Service Discovery, and Content Distribution into distinct, mathematically verifiable layers secured by standard elliptic curve cryptography.

---

## 1. Introduction

If a system conflates a human-readable alias with the underlying identity, it exposes itself to Semantic Attacks (e.g., Long-Range Resurrection). If `alice.kin` transfers ownership of her alias to Bob, and the system conflates name with identity, users may unknowingly send encrypted data or funds to Bob, assuming Alice still owns the alias. The foundational axiom of the Kinetic Identity Architecture is that a name is merely an ephemeral, transferable routing alias. An identity is a permanent, immutable cryptographic anchor.

## 2. The Four-Layer Architecture

### 2.1 Layer 1: The Human Namespace (`saif.kin`)
The first layer is secured by the Proof-of-Patience VDF registration system. Names are designed strictly for human memorability, branding, and high-level routing. Because ownership may change via grace-period escalation or intentional transfer, names are explicitly *not* permanent identities.

### 2.2 Layer 2: The Permanent Identity (KID)
A Kinetic name does not resolve to an IP address. It resolves to a **Kinetic Identity Document (KID)**.
`saif.kin` $\rightarrow$ `did:kin:kid1abc9f7...`

The KID is the permanent cryptographic root of trust, bound irreversibly to a high-speed, high-security Ed25519 [1] or secp256k1 keypair. It represents the actual entity. If `saif.kin` changes ownership, the DHT payload is updated to point to a different KID, preventing semantic masquerading.

**KID Schema Definition (`document.rs`):**
```json
{
  "kid": "did:kin:kid1abc9f7...",
  "pubkey": "ed25519:8b3a...",
  "created_at": 1750000000,
  "revocation_key": "ed25519:4f2c..."
}
```

### 2.3 Layer 3: The Capability Manifest
A KID points to a **Capability Manifest**. The manifest cryptographically declares exactly what services this identity currently exposes to the network. By resolving through a manifest rather than a direct A-record, the architecture becomes strictly service-agnostic. 

**Manifest Schema Definition (`manifest.rs`):**
```json
{
  "version": "1.0",
  "owner": "did:kin:kid1abc9f7...",
  "services": [
    {
      "type": "website",
      "protocol": "https",
      "target": "104.21.44.11"
    },
    {
      "type": "nostr-relay",
      "protocol": "wss",
      "target": "relay.nostr.info"
    }
  ],
  "signature": "0x7a8b9c..."
}
```

### 2.4 Layer 4: Content and Compute
Services resolve to actionable content (Website files, APIs, AI Chatbots). Content distribution and computing are not the responsibility of the Kinetic Protocol. Kinetic answers *"Who owns this name?"* and *"What services exist for this identity?"* It relies on parallel infrastructure operators or decentralized storage networks (e.g., IPFS) to serve the physical bytes.

## 3. Light Client Resolution Architecture

Because ownership state is perfectly encapsulated inside self-authenticating, mathematically verifiable payloads, Kinetic supports trust-minimized light clients.

A light client (such as a standard web browser or mobile application) requests lease records via standard HTTPS from an untrusted gateway. The client locally verifies the Ed25519 cryptographic signatures, the `drand` heartbeat timestamps, and the associated VDF proofs. The gateway acts merely as a data transport, not a trusted resolver, meaning it cannot forge ownership. To mitigate gateway censorship, clients fetch records from a Minimum Gateway Set (e.g., 3 independent public endpoints), deterministically validating and choosing the winning payload locally.

## 4. Conclusion
By forcefully decoupling names from cryptographic identity documents (KIDs), the Kinetic protocol solves the semantic vulnerabilities inherent to legacy domain systems. This multi-layered architecture provides a robust framework for verifiable, generalized service discovery.

---

## References

[1] Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., & Yang, B.-Y. (2012). *High-speed high-security signatures.* Journal of Cryptographic Engineering, 2(2), 77–89.
