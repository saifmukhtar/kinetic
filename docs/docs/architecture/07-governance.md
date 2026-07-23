---
title: '07 — Governance'
prev:
  text: '06 — Daemon & DNS'
  link: '/architecture/06-daemon-and-dns'
next:
  text: '08 — Client Architecture'
  link: '/architecture/08-client-architecture'
---

# Architecture & Motivation: Bicameral Governance

How does a decentralized protocol upgrade itself without relying on centralized auto-updaters, yet avoid the gridlock and plutocracy of DAO token-voting?

Kinetic solves this via a **Bicameral (Two-Phase) Governance Engine** built directly into the core state machine (`kinetic-core/src/governance/engine/bicameral.rs`).

## The Failure of Token-Voting DAOs

Most decentralized projects issue a governance token. One token equals one vote. This inevitably leads to oligarchy: wealthy entities buy massive amounts of the token, collude, and pass self-serving updates. Conversely, pure social consensus (forking the repo on GitHub) is too slow to respond to critical zero-day vulnerabilities.

Kinetic has no token. Instead, governance is based on a rigid, cryptographic hierarchy of trusted keys (the Council) that is algorithmically forced to decentralize over time.

## Phase 1: The Founder Era

When a Kinetic network launches, it is highly vulnerable. Bugs are likely, and the network needs the ability to pivot rapidly. 

In Phase 1, the protocol is governed by a `Root Key` and a set of `Guard Keys` (the Founder keys). 
- The Root key can propose Over-The-Air (OTA) binary updates.
- The Guard keys can veto them.

This provides the agility of a startup while the network is young. However, users shouldn't have to trust the Founders forever.

## The Auto-Lock Transition

The protocol contains a ticking clock. 

According to `kinetic-core/src/constants.rs`, there is an `AUTO_LOCK_SECONDS` constant (typically 365 days) and a `MIN_ACTIVE_COUNCIL` limit (typically 7 members). 

If the network has existed for 365 days, OR if the Founders have added 7 independent community members to the Council, **Phase 1 permanently terminates**. The Root key is cryptographically stripped of its unilateral power. The network transitions irreversibly to Phase 2.

## Phase 2: The Bicameral Council

In Phase 2, the network is governed by a globally distributed Council of humans (maximum 21 members). Any protocol action now requires a mathematically enforced supermajority of Council signatures.

### The Thresholds
The thresholds are hardcoded in the rust binaries:
- **69% Supermajority:** Required to push an OTA software update or add/remove a Council member.
- **90% Supermajority:** Required to forcibly seize or reassign a "premium" or highly contested namespace (preventing the council from easily stealing names).
- **95% Supermajority:** Required to execute a catastrophic key rotation (e.g., if multiple council members lose their keys).

### The 48-Hour OTA Timelock

Even if 69% of the Council is compromised and attempts to push malicious malware as an OTA update, the protocol enforces an `OTA_TIMELOCK_SECONDS` of 48 hours.

Once the malicious update is signed, the network refuses to execute it for 48 hours. During this window, any user can inspect the proposed binary hash. If the community determines the Council has gone rogue, 48 hours is enough time for users to socially coordinate, hard-fork the `kinetic-network` crate, strip the malicious Council of their keys, and restart the network.

This ensures that the Council has agility, but the ultimate power remains with the users' ability to reject malicious consensus.
