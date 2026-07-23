# Architecture & Motivation: Threat and Trust Model

To trust a decentralized system, you must know exactly what it assumes to be true, and what threats it considers out-of-scope. Kinetic's threat model is highly pragmatic.

## What We Trust (In-Scope Assumptions)

1.  **The Cryptography Holds:** We assume that SHA-256, Ed25519, ML-DSA-65, and Argon2id are not fundamentally broken.
2.  **The League of Entropy (Drand):** We assume the Drand Quicknet threshold network remains honest and live. If the League of Entropy is completely compromised (an attacker steals the majority of the threshold shards), they could predict the randomness beacon and pre-compute VDFs, allowing them to hoard short names.
3.  **Local OS Security:** We assume the user's local operating system is not compromised by a rootkit. If a user's machine has malware running with Administrator privileges, the malware can steal the `identity.key` from disk. No application-level software can defend against a compromised Ring-0 OS.
4.  **Bicameral Rationality:** We assume that 69% of the Governance Council will not intentionally destroy the network. If a supermajority goes rogue, the ultimate fallback is a social hard-fork by the users.

## What We Do Not Trust (Adversarial Environment)

Kinetic is designed to operate in a hostile, zero-trust environment.

1.  **We Do Not Trust the DHT:** Any node on the Kademlia DHT can lie. When a resolver asks the DHT for a name, the DHT node might return a fake IP address or a forged Capability Manifest. 
    *   *Defense:* All records must be cryptographically signed by the ML-DSA-65 key committed to by the VDF proof. The resolver mathematically verifies the signature locally. If the signature is invalid, the DHT response is instantly dropped.
2.  **We Do Not Trust the User's Input:** Users can input malicious strings into the CLI or API (e.g., trying to register a name with SQL injection payloads or path traversal characters like `../../name.kin`).
    *   *Defense:* The `kinetic-core` crate enforces strict regex and byte-length validation on all names and fields before they even reach the network layer.
3.  **We Do Not Trust the Upstream DNS:** When acting as a proxy, the upstream DNS resolver (like an ISP's DNS) might try to perform DNS rebinding.
    *   *Defense:* Kinetic strips local and loopback IP addresses from untrusted external responses, preventing SSRF attacks against the user's local network.
4.  **We Do Not Trust the Network Connection:** ISPs or network eavesdroppers might try to MITM the connection between Kinetic nodes.
    *   *Defense:* `libp2p` Noise is used to enforce end-to-end encryption on all P2P traffic, ensuring confidentiality and perfect forward secrecy.

By explicitly defining these boundaries, Kinetic ensures that the computationally heavy operations (VDFs) and the critical security checks (ML-DSA-65 signatures) are applied exactly where they matter most: at the edges of the network where the data is actually consumed.
