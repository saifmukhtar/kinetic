# Architecture & Motivation: Cryptography and Identity

Kinetic's identity layer is the foundation upon which all naming, data portability, and network operations rest. The cryptographic choices made here prioritize long-term security, deterministic verification, and post-quantum readiness.

## The Shift to Post-Quantum Identity: ML-DSA-65

In many decentralized networks, Ed25519 or secp256k1 are the standard choices for identity and wallet keys. Kinetic intentionally breaks from this norm for its core identity layer.

**We exclusively use ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm) for identity keys, name-ownership signatures, and root governance.**

### Why ML-DSA-65?
The threat of cryptographically relevant quantum computers (CRQCs) is no longer a distant theoretical concern; it is a looming reality. Naming systems and identities are long-lived assets. A user who registers `alice.kin` today expects to own it decades from now. If we used classical elliptic curve cryptography (ECC) for identity, a future quantum computer running Shor's algorithm could derive the private key from the public key and steal the identity.

ML-DSA-65 (formerly Dilithium3) provides NIST Level 3 post-quantum security. By using it natively for all `did:kin` identities, Kinetic ensures that ownership and governance remain secure against both classical and quantum adversaries. 

### Where is Ed25519 used?
While ML-DSA-65 is robust, its signatures and public keys are significantly larger than ECC equivalents. To balance security with network performance, **Ed25519 is strictly relegated to libp2p PeerIds and transient network routing.** 

The libp2p layer uses Ed25519 to establish secure channels (Noise protocol) and identify peers on the DHT. However, this is an ephemeral routing identity. Even if a quantum attacker compromised a node's Ed25519 PeerId, they could only disrupt routing temporarily; they could not steal the underlying ML-DSA-65 user identity or `.kin` names.

## Deterministic Identity: `did:kin`

A Kinetic identity is formatted as a Decentralized Identifier (DID):
`did:kin:<hash>`

The `<hash>` is strictly derived as the `SHA-256` hash of the user's ML-DSA-65 public key.

### Preventing DID Hijacking
This derivation is not merely a convention; it is a hard cryptographic invariant enforced by the `kinetic-kid` crate. When a resolver receives a signed DID Document or Capability Manifest, it MUST recompute the SHA-256 hash of the provided controller public key and verify that it matches the DID string itself.

If this check were absent, an attacker could intercept a DID document, swap the legitimate public key with their own, and trick the network into accepting signatures from the attacker's key for that DID. By tightly coupling the identifier to the cryptographic material, Kinetic eliminates the possibility of DID hijacking.

## JSON Canonicalization Scheme (JCS)

To prove ownership or delegate capabilities, identities must sign JSON documents (Capability Manifests). However, JSON serialization is notoriously non-deterministic. A JSON object serialized in Rust might have its keys ordered differently or use different whitespace than the same object serialized in JavaScript.

If a user signs a JSON object, and a verifier serializes it differently before checking the signature, the verification will fail.

To solve this, Kinetic mandates the **JSON Canonicalization Scheme (RFC 8785)** for all signed documents. 
1. The document is stripped of its `signature` field.
2. It is converted to a strict canonical byte representation (keys sorted alphabetically, whitespace normalized).
3. The ML-DSA-65 signature is generated over these canonical bytes.

This ensures that regardless of the platform, language, or underlying JSON library, the signed bytes are perfectly identical, guaranteeing reliable cross-platform identity verification.
