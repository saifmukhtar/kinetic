# Kinetic Project Governance

This document describes the governance model for the Kinetic Protocol. It details how decisions are made, how the network is secured via cryptographic rules, and how leadership roles are structured. 

Unlike many open-source projects where governance is purely social, Kinetic's governance is **cryptographically enforced on-chain** through the "Bicameral Rule Book." This ensures that the network remains decentralized, mathematically rigorous, and secure.

## 1. Project Overview & Mission

Kinetic is built on the philosophy of statelessness, decentralization, and extreme technical rigor. We value objective engineering and cryptographic security above all else. 

The governance structure is designed to:
1. Provide rapid, decisive leadership during the protocol's infancy (Phase 1).
2. Automatically transition to a fully decentralized, trustless council model (Phase 2).
3. Ensure that no malicious updates can easily compromise the network.

## 2. Project Roles and Responsibilities

### The Founder (Saif Mukhtar)
During Phase 1 (the first 12 months after genesis), the Founder holds two critical cryptographic keys:
- **The Root Key:** Acts as a benevolent dictator key capable of bypassing standard voting thresholds for rapid iteration and emergency fixes.
- **The Guard Key (Veto Key):** A protective key that can instantly veto any proposed malicious updates and trigger a 30-day emergency timelock. 

### The Council (Multisig Core Maintainers)
The Council is a dynamic group of up to `N` core maintainers whose public keys are registered on the network.
- They have voting rights on architectural changes and protocol upgrades (Over-The-Air updates).
- A **69% supermajority** is required for the Council to ratify a binary OTA update.
- If an update is ratified, it enters a **24-hour timelock** before nodes apply it, allowing the Guard Key to veto if necessary.

### Contributors and Users
- **Users:** Community members who engage via issues, discussions, or running standard non-validating nodes.
- **Contributors:** Individuals who submit code, documentation, or reviews. They can propose non-consensus changes via Pull Requests.

## 3. The Path to Leadership (Meritocracy)

Maintainership and Council membership are granted through a strict **merit-based appointment** process. To be nominated to the On-Chain Council, a community member must:
1. Demonstrate **sustained technical contributions** (3-6 months) to the core protocol.
2. Run a **stable network node** (Daemon or Infrastructure Node).
3. Be formally **nominated by existing Council members**.

Once nominated, the addition of the new member's public key must be ratified by a 69% supermajority vote of the existing Council via a `SignedGovernanceMessage`.

## 4. Decision-Making Process (The Bicameral Rule Book)

### Routine Changes
Minor bug fixes, documentation updates, and standard refactoring can be merged by any core maintainer without triggering an on-chain network upgrade.

### Architectural Changes & OTA Updates
Significant changes (e.g., modifying VDF parameters, altering the DHT routing logic) require an official network update.
1. **Proposal:** A new binary is compiled, hashed, and proposed to the network alongside mirrors for downloading.
2. **Ratification:** The Council must achieve a 69% supermajority by signing the proposal.
3. **Timelock:** Once ratified, the update enters a 24-hour timelock.
4. **Execution:** If not vetoed by the Guard Key, the network automatically downloads, verifies the hash, and hot-swaps the running binary via `self_replace`.

### Phase 1 vs Phase 2
- **Phase 1 (Incubation):** For the first 12 months, the Founder (Saif Mukhtar) can use the Root Key to bypass the Council for emergency fixes.
- **Phase 2 (Decentralization):** After 12 months, if there are at least 7 active Council members, the network **auto-locks**. The Root Key loses its bypass authority, and the network becomes permanently decentralized, governed entirely by the Council.

## 5. Conflict Resolution & Emergencies

- **Guard Veto:** If a malicious update is ratified by a compromised Council, the Guard Key can veto the update.
- **Emergency Reset:** If the network is catastrophically compromised, the Founder can issue an Emergency Reset to rotate keys, which triggers a strict 30-day timelock before taking effect. 

For interpersonal conflicts or Code of Conduct violations, refer to the `CODE_OF_CONDUCT.md`.
