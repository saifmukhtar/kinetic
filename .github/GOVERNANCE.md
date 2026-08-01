# Kinetic Project Governance

This document describes the governance model for the Kinetic Protocol. It details how decisions are made, how the network is secured via cryptographic rules, and how leadership roles are structured. 

Unlike many open-source projects where governance is purely social, Kinetic's governance is **cryptographically enforced at the protocol level** through the "Governance Rule Book." This ensures that the network remains decentralized, mathematically rigorous, and secure.

## 1. Project Overview & Mission

Kinetic is built on the philosophy of statelessness, decentralization, and extreme technical rigor. We value objective engineering and cryptographic security above all else. 

The governance structure is decoupled into two pluggable engines depending on the deployment configuration:
1. **Sovereign Mode:** Designed for the protocol's infancy, private networks, or rapid iteration phases.
2. **Permissionless Mode:** A fully decentralized, immutable state with no governance authorities.

## 2. Pluggable Governance Engines

Kinetic does not rely on a complex on-chain parliament or multi-signature council. Instead, networks configure their governance at compile-time via `network.json`. 

### Sovereign Engine
In `sovereign` mode, the network is governed exclusively by a single offline **Root Key**. 
- The Root Key acts as a benevolent dictator capable of pushing Over-The-Air (OTA) updates, rotating keys, and halting the network.
- There are no voting thresholds, supermajorities, or quorum requirements. The network inherently trusts the mathematics of the Root Key signature.
- This mode is ideal for the T0 (Public) deployment's initial rollout, ensuring swift mitigation of early-stage vulnerabilities.

### Permissionless Engine
In `permissionless` mode, the network operates as an immutable force of nature.
- There are no administrative keys, no Root Key, and no governance actions permitted.
- The protocol cannot be halted, and OTA updates are rejected natively by the engine.
- This is the endgame for public networks: pure mathematics, completely outside human control.

## 3. Decision-Making Process (The Governance Rule Book)

### Routine Changes
Minor bug fixes, documentation updates, and standard refactoring can be merged via pull requests. However, they will not be pushed to the network unless an OTA update is authorized.

### Architectural Changes & OTA Updates
Significant changes (e.g., modifying VDF parameters, altering the DHT routing logic) require an official network update.
1. **Proposal:** A new binary is compiled, hashed, and proposed to the network alongside mirrors for downloading.
2. **Authorization (Sovereign Only):** The Root Key signs the proposal hash.
3. **Execution:** Once the network verifies the Root signature (or rejects it instantly if in Permissionless mode), the network automatically downloads, verifies the hash, and hot-swaps the running binary via `self_replace`.

## 4. Conflict Resolution & Emergencies

- **Emergency Reset:** If the network is catastrophically compromised while in Sovereign mode, the Root Key can issue an Emergency Halt or Key Rotation.
- **Permissionless Forking:** If a network running in Permissionless mode encounters a catastrophic bug, the community must socially coordinate a hard fork via a new genesis block, as the protocol itself cannot be altered.

For interpersonal conflicts or Code of Conduct violations, refer to the `CODE_OF_CONDUCT.md`.
