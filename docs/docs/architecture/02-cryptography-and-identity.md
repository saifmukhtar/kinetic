---
title: '02 — Cryptography & Identity'
prev:
  text: '01 — Philosophy'
  link: '/architecture/01-philosophy'
next:
  text: '03 — VDF & Cost'
  link: '/architecture/03-vdf-and-cost'
---

# Architecture & Motivation: Cryptography and Identity

Kinetic's identity layer is the cryptographic foundation upon which all naming, data portability, and network operations rest. The choices made here prioritize long-term security, deterministic verification, and post-quantum readiness over short-term optimizations. We assume a hostile network environment where attackers possess both classical supercomputers and near-future quantum capabilities.

## The Shift to Post-Quantum Identity: ML-DSA-65

In nearly all modern decentralized networks, elliptic curve cryptography (specifically Ed25519 or secp256k1) is the standard choice for identity and wallet keys. Kinetic intentionally breaks from this norm for its core identity layer.

**We exclusively use ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm) for identity keys, name-ownership signatures, and root governance.**

### Why ML-DSA?
The threat of cryptographically relevant quantum computers (CRQCs) running Shor's algorithm is no longer a distant theoretical concern; it is an impending reality. Naming systems and decentralized identities are, by definition, long-lived assets. A user who registers `alice.kin` today rightfully expects to own it decades from now. If we were to anchor these identities using classical elliptic curve cryptography (ECC), a future quantum attacker could easily derive the private key from the public key, enabling them to steal the identity, hijack domains, and impersonate the user permanently.

To future-proof the network from Genesis, we selected ML-DSA (formerly known as CRYSTALS-Dilithium), which was standardized by NIST (FIPS 204) as the primary post-quantum digital signature algorithm. 

### Why the ML-DSA-65 Parameter Set?
NIST standardized three parameter sets for ML-DSA: ML-DSA-44 (Level 2), ML-DSA-65 (Level 3), and ML-DSA-87 (Level 5). 

We chose **ML-DSA-65** as the perfect middle ground. 
*   **Security:** It provides NIST Level 3 security (comparable to AES-192), ensuring robust protection against both classical and quantum attacks.
*   **Performance Trade-off:** While ML-DSA-87 offers maximum security, it results in massive public keys and signatures that would severely bloat the DHT and dramatically increase bandwidth requirements for mobile and edge nodes. ML-DSA-65 strikes the optimal balance between high-grade security and practical network overhead. Public keys are exactly 1952 bytes, and signatures are 3309 bytes.

### Where is Ed25519 used?
While ML-DSA-65 is robust, its signatures and public keys are significantly larger than their 32-byte and 64-byte ECC equivalents. Using ML-DSA for every single network packet and routing handshake would paralyze the network.

To balance security with network performance, **Ed25519 is strictly relegated to `libp2p` PeerIds and transient network routing.** 

The libp2p layer uses Ed25519 to establish secure channels (via the Noise protocol) and identify transient peers on the Kademlia DHT. This is an ephemeral routing identity. Even if a quantum attacker compromised a node's Ed25519 PeerId in the future, they could only disrupt routing temporarily or spoof a node's IP address; they could **never** steal the underlying ML-DSA-65 user identity, modify `.kin` domains, or forge a capability manifest.

## Deterministic Identity: `did:kin`

A Kinetic identity is formatted as a Decentralized Identifier (DID):
`did:kin:<hash>`

The `<hash>` is strictly derived as the `SHA-256` hash of the user's ML-DSA-65 public key, represented in lowercase hex.

### Preventing DID Hijacking
This derivation is not merely a naming convention; it is a hard cryptographic invariant enforced by the `kinetic-kid` (Kinetic Identity) crate. When a resolver receives a signed DID Document, a DNS zone file, or a Capability Manifest, it MUST recompute the SHA-256 hash of the provided controller public key and verify that it matches the DID string itself.

If this mathematical check were absent, an attacker could intercept a DID document on the DHT, swap the legitimate public key with their own, and trick the network into accepting signatures from the attacker's key for that DID. By tightly coupling the identifier to the cryptographic material, Kinetic entirely eliminates the possibility of DID hijacking and "bait-and-switch" attacks.

## JSON Canonicalization Scheme (JCS)

To prove ownership, delegate capabilities, or configure DNS settings, identities must sign complex data structures (typically represented as JSON). However, JSON serialization is notoriously non-deterministic. A JSON object serialized in Rust might have its keys ordered differently or use different whitespace than the exact same object serialized in JavaScript, Python, or Go.

If Alice signs a JSON object, and Bob's verifier serializes that object slightly differently before checking the signature, the verification will fail. The hash of the payload will have changed.

To solve this, Kinetic strictly mandates the **JSON Canonicalization Scheme (RFC 8785)** for all signed documents across the protocol. 

The verification flow is uncompromising:
1. The incoming JSON document is stripped of its `signature` field (if embedded).
2. The remaining JSON object is converted to a strict canonical byte representation. This means all keys are sorted lexicographically, all whitespace is normalized or removed, and numbers are formatted according to strict IEEE 754 rules.
3. The ML-DSA-65 signature is verified specifically against these exact canonical bytes.

This ensures that regardless of the operating system, programming language, or underlying JSON library, the bytes fed into the signature algorithm are perfectly identical. This guarantees reliable, cross-platform identity verification and prevents malleability attacks where an adversary subtly modifies whitespace to break signatures.
