---
title: '10 — Threat & Trust Model'
prev:
  text: '09 — Forks & Compilation'
  link: '/architecture/09-forks-and-compilation'
next:
  text: 'Adversarial Analysis (Red-Team Audit)'
  link: '/adversarial_analysis'
---

# Architecture & Motivation: Threat and Trust Model

To rigorously evaluate and trust any decentralized system, you must know exactly what it assumes to be true, and what threats it considers out-of-scope. No system is perfectly secure against all possible adversaries. Kinetic's threat model is highly pragmatic and designed around the realities of modern networking and cryptography.

## What We Trust (In-Scope Assumptions)

The security of the Kinetic protocol rests entirely on the following four foundational assumptions holding true:

1.  **The Cryptography Holds:** We mathematically assume that SHA-256 (for hashing and DID derivation), Ed25519 (for ephemeral routing), ML-DSA-65 (for post-quantum identity signatures), and Argon2id (for memory-hard PoW) are not fundamentally broken. We assume no cryptographic backdoors exist in these standardized algorithms.
2.  **The League of Entropy (Drand) Remains Honest:** We assume the Drand Quicknet threshold network remains honest and live. For Drand to be compromised, a highly coordinated adversary must simultaneously compromise and steal the private key shards from a supermajority of the participating organizations (which include Cloudflare, Protocol Labs, UCL, etc.). If the League of Entropy were completely compromised, the attacker could predict the randomness beacon and pre-compute VDFs, allowing them to hoard short names. We consider this threshold model to be an acceptable and highly secure source of public randomness.
3.  **Local OS Security:** We assume the user's local operating system is not compromised by a rootkit or privilege escalation malware. If a user's machine has malware running with Administrator or Ring-0 privileges, the malware can bypass the `axum` local API boundary, read arbitrary memory, and steal the `identity.key` directly from the filesystem. No application-level software can defend against a fundamentally compromised host operating system.
4.  **Council Rationality:** We assume that 69% of the globally distributed Governance Council will not intentionally collude to destroy the network. If a supermajority does go rogue, the ultimate fallback relies on the social assumption that the user base will coordinate a hard-fork within the 48-hour OTA timelock window.

## What We Do Not Trust (Adversarial Environment)

Kinetic is designed to operate in a hostile, zero-trust network environment where every other peer is treated as potentially malicious.

1.  **We Do Not Trust the DHT (Eclipse & Sybil Threats):** Any node on the Kademlia DHT can lie. When a resolver asks the DHT for a name, the DHT node might return a fake IP address, a forged Capability Manifest, or claim the record doesn't exist. 
    *   *Defense:* Kinetic enforces a strict Zero-Trust Data Model. All records returned by the DHT must be cryptographically signed by the ML-DSA-65 key committed to by the accompanying VDF proof. The resolver mathematically verifies the signature locally before ever acting on the data. If the signature is invalid or missing, the DHT response is instantly dropped. To prevent Eclipse attacks, we require the massive 16 MiB Argon2id PoW just to enter the routing table, making it economically disastrous for an attacker to surround a target hash.
2.  **We Do Not Trust the User's Input:** Users (and automated bots) can input malicious strings into the CLI or API (e.g., trying to register a name with SQL injection payloads, XSS vectors, or path traversal characters like `../../name.kin`).
    *   *Defense:* The `kinetic-core` crate enforces strict, deterministic regex and byte-length validation on all `.kin` names and JSON fields before they even reach the network layer or the storage engine. 
3.  **We Do Not Trust Upstream DNS Resolvers:** When acting as a proxy, the upstream DNS resolver (like an ISP's DNS) might try to perform DNS rebinding attacks against the user.
    *   *Defense:* Kinetic aggressively strips local, loopback, and reserved private IP addresses (e.g., `127.0.0.1`, `192.168.x.x`) from untrusted external responses, preventing SSRF attacks against the user's local network router or background services.
4.  **We Do Not Trust the Network Transport:** ISPs, malicious Wi-Fi access points, or nation-state network eavesdroppers might try to Man-in-the-Middle (MITM) or passively record the connection between Kinetic nodes.
    *   *Defense:* Kinetic strictly enforces the `libp2p` Noise protocol to establish authenticated, end-to-end encryption on all P2P traffic, ensuring absolute confidentiality and perfect forward secrecy against passive dragnet surveillance.

By explicitly defining these strict trust boundaries, Kinetic ensures that the computationally heavy operations (VDFs) and the critical security checks (ML-DSA-65 signatures) are applied exactly where they matter most: at the very edges of the network where the data is actually consumed.
