# Technical Paper II: The Identity Architecture (KID)

**Author:** Saif Mukhtar
**Date:** July 2026
**Version:** 2.0.0

## Abstract

Traditional decentralized naming systems attempt to replicate legacy DNS logic by directly mapping a human-readable identifier to a network location (IP address). The Kinetic Protocol introduces an alternative paradigm: an **Identity-Centric Service Discovery Network**. This paper formalizes the Kinetic Identity Document (KID) architecture — a four-layer progression that securely separates Human Discovery, Identity, Service Discovery, and Content Distribution into distinct, mathematically verifiable layers.

This architecture is fully fork-portable. Every network deployed via `kinetic-forge` inherits the same KID system. The `did_prefix` field in `network.json` (e.g., `did:kin:` for the canonical network, `did:mit:` for a university fork) namespaces all identity documents to their network, preventing cross-network identity collisions by construction.

---

## 1. The Foundational Axiom: Name ≠ Identity

If a system conflates a human-readable alias with the underlying identity, it exposes itself to **Semantic Attacks** (e.g., Long-Range Resurrection). If `alice.kin` transfers ownership to Bob, and the system conflates name with identity, users may unknowingly send encrypted data or funds to Bob, assuming Alice still controls the alias.

The foundational axiom of the Kinetic Identity Architecture is:

> **A name is an ephemeral, transferable routing alias. An identity is a permanent, immutable cryptographic anchor.**

These two concepts are explicitly separated at the data-model level. They must never be merged.

---

## 2. The Four-Layer Architecture

### 2.1 Layer 1: The Human Namespace (`example.kin`)

The first layer is secured by the Proof-of-Patience VDF registration system described in `kinetic-consensus.md`. Names are designed strictly for human memorability, branding, and high-level routing.

Because ownership may change via Grace-Period Escalation or intentional transfer, names are explicitly **not** permanent identities. They are pointers — the first leg of a resolution chain.

**Validation Rules** (enforced in `kinetic-core/src/types/names.rs`):
- Characters: `a-z`, `0-9`, `-` only (DNS LDH rule)
- First character: never a digit, never a hyphen
- Last character: never a hyphen
- Only apex domains (`example.kin`) are registerable — not subdomains (`blog.example.kin`)
- Reserved names (RFC 2606: `localhost`, `test`, `invalid`, `local`, `null`) are permanently locked
- Infrastructure names (`docs`, `seed`, `explorer`, etc.) are locked until Phase 2 governance

### 2.2 Layer 2: The Permanent Identity (KID)

A Kinetic name does not resolve to an IP address. It resolves to a **Kinetic Identity Document (KID)**.

```
example.kin  →  did:kin:kid1abc9f7...
```

The KID is the permanent cryptographic root of trust, bound to a high-speed, high-security **Ed25519** keypair [1]. It represents the actual entity. If `example.kin` changes ownership, the DHT payload is updated to point to a different KID, preventing semantic masquerading.

**KID Document Schema** (as implemented in `kinetic-kid/`):
```json
{
  "kid": "did:kin:kid1abc9f7...",
  "pubkey": "ed25519:8b3a...",
  "created_at": 1750000000,
  "revocation_key": "ed25519:4f2c..."
}
```

**Fork Note:** On a university fork using `did:mit:` prefix, all KIDs are namespaced to that network. A `did:mit:` identity document is cryptographically distinct from a `did:kin:` document and cannot be replayed across networks.

### 2.3 Layer 3: The Capability Manifest

A KID points to a **Capability Manifest**. The manifest cryptographically declares exactly what services this identity currently exposes to the network. By resolving through a manifest rather than a direct A-record, the architecture becomes strictly service-agnostic.

**Manifest Schema** (as implemented in `kinetic-kid/src/manifest.rs`):
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
      "type": "api",
      "protocol": "https",
      "target": "api.myservice.com"
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

The manifest is signed by the KID's Ed25519 private key. Any peer in the network can independently verify the signature without contacting a trusted authority.

**Why this matters for forks:** A university running `.uni` can define custom service types in their Capability Manifests — for example, a `type: "research-endpoint"` or `type: "hpc-cluster"`. The base protocol is service-type agnostic by design.

### 2.4 Layer 4: Content and Compute

Services resolve to actionable content: websites, APIs, AI agents, databases. Content distribution and computing are explicitly **not** the responsibility of the Kinetic Protocol.

Kinetic answers:
- *"Who owns this name?"*
- *"What services does this identity expose?"*

It deliberately does not answer:
- *"Where is the file stored?"*
- *"How is the compute provisioned?"*

These responsibilities belong to parallel infrastructure: object storage, IPFS, CDN networks, or self-hosted servers. This separation of concerns is intentional — it keeps the Kinetic core minimal, auditable, and forkable.

---

## 3. Light Client Resolution Architecture

Because ownership state is perfectly encapsulated inside self-authenticating, mathematically verifiable payloads, Kinetic supports **trust-minimized light clients**.

A light client (such as a standard web browser or mobile application via the Kinetic client) requests lease records via standard HTTPS from an untrusted gateway. The client locally verifies:
1. The **Ed25519 cryptographic signatures** on the KID and Capability Manifest
2. The **`drand` heartbeat timestamps** to confirm the record is not stale
3. The **VDF proof** to confirm the name was legitimately registered

The gateway acts as a data transport, not a trusted resolver. It cannot forge ownership because it does not hold private keys.

To mitigate gateway censorship, clients fetch records from the **Minimum Gateway Set** — at least 3 independent public endpoints defined in `network.json` under `drand_http_endpoints`. Records are deterministically compared locally, with the highest-valid payload winning.

---

## 4. DNS Record System

The Kinetic DNS zone system supports up to **50 DNS records per apex domain**, as enforced in `kinetic-core/src/types/dns.rs`. Supported record types include standard DNS types (`A`, `AAAA`, `CNAME`, `TXT`, `MX`, `SRV`) with cryptographic binding to the KID.

This limit is a practical engineering constraint: DHT payloads are capped at 64KB (`MAX_PAYLOAD_SIZE`), and larger zone files would degrade DHT propagation performance. For production deployments requiring complex DNS configurations, the recommended pattern is to register the apex domain on Kinetic and use standard DNS delegation (`NS` records) to a conventional DNS provider for the record-heavy configuration.

---

## 5. Conclusion

By forcefully decoupling names from cryptographic identity documents, the Kinetic Protocol eliminates the semantic vulnerabilities inherent to legacy domain systems. This multi-layered architecture provides a robust framework for verifiable, generalized service discovery that any network operator can deploy and customize without modifying the core cryptographic engine.

---

## References

[1] Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., & Yang, B.-Y. (2012). *High-speed high-security signatures.* Journal of Cryptographic Engineering, 2(2), 77–89.

[2] W3C. (2022). *Decentralized Identifiers (DIDs) v1.0.* W3C Recommendation. Retrieved from https://www.w3.org/TR/did-core/
