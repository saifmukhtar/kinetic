# Security Policy

The security of the Kinetic Protocol is our absolute highest priority. As a decentralized, cryptographic naming infrastructure, we treat vulnerabilities in the VDF engine, the Kademlia DHT routing logic, and the Ed25519 payload validation with extreme severity.

## Supported Versions

Currently, Kinetic is in active development. We provide security patches for the latest released version on the `main` branch. 

| Version | Supported          |
| ------- | ------------------ |
| `main`  | :white_check_mark: |
| `< 1.0` | :x:                |

## Reporting a Vulnerability

**DO NOT** open a public GitHub issue or discuss potential vulnerabilities in public forums or Discord if you believe you have found a zero-day exploit, a flaw in the cryptographic proofs, or a way to perform an Eclipse/Sybil attack against the DHT.

Please report security vulnerabilities by emailing the Lead Maintainer directly at:

**[saifmukhtar20@gmail.com](mailto:saifmukhtar20@gmail.com)**

When reporting a vulnerability, please include:
- A detailed description of the vulnerability.
- Step-by-step instructions or a Proof of Concept (PoC) to reproduce the issue.
- The expected behavior vs. the actual behavior.
- Any potential impact on the network (e.g., "Allows an attacker to overwrite another user's `.kin` payload without a valid VDF").

### Our Response

We will endeavor to respond to your initial email within **48 hours**. 

We operate under strict Responsible Disclosure guidelines. If the vulnerability is verified, we will work privately to develop a patch. Once the patch is deployed and the network has updated, we will publicly acknowledge your discovery (if you desire) and publish a detailed post-mortem.
