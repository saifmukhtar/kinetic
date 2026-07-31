---
title: '07 — Governance'
prev:
  text: '06 — Daemon & DNS'
  link: '/architecture/06-daemon-and-dns'
next:
  text: '08 — Client Architecture'
  link: '/architecture/08-client-architecture'
---

# Architecture & Motivation: Governance

How does a decentralized protocol seamlessly upgrade itself without relying on centralized auto-updaters controlled by a single corporation, yet simultaneously avoid the gridlock, plutocracy, and systemic failures of traditional DAO token-voting?

Kinetic solves this intricate political and technical challenge via a **Pluggable Governance Engine** built directly into the core state machine (`kinetic-core/src/governance/engine/`).

## The Failure of Token-Voting DAOs

Most decentralized projects issue a native governance token. The prevailing model is "one token equals one vote." This inevitably and demonstrably leads to oligarchy: wealthy entities (whales or venture capital firms) buy massive amounts of the token, collude with one another, and pass self-serving updates that extract value from the network's users. 

Conversely, pure "social consensus" (like Bitcoin, where the only way to upgrade is by forking the open-source repository and convincing the world to download the new binary) is far too slow and uncoordinated to respond to critical zero-day vulnerabilities in a rapidly evolving network protocol.

Kinetic has absolutely no token. There is no currency to stake, and no votes to buy. Instead, governance is based on a rigid, cryptographic hierarchy of trusted identities (the Council) that is algorithmically forced to decentralize itself over time to prevent long-term tyranny.

## Supported Governance Models

The Kinetic protocol supports multiple governance engines that can be selected at compile time via `network.json`, allowing the network to operate in different phases or modes depending on its maturity and goals.

### 1. Sovereign (The Founder Era)

When a Kinetic network launches (Genesis), the software might be highly vulnerable. Unforeseen bugs are likely, economic edge cases will emerge, and the network needs the agility to pivot rapidly to survive its infancy. 

In `sovereign` mode, the protocol is strictly governed by a `Root Key` (typically held by the core development team in cold storage). 
- The Root key has the unilateral, absolute power to propose Over-The-Air (OTA) binary updates and emergency parameter tweaks.

This model provides the immense agility of a centralized startup while the network is young. However, a foundational tenet of Kinetic is that users should not have to trust the Founders forever.

### 2. Council (The Republic Era)

In `council` mode, the network matures into a distributed republic. It is governed by a globally distributed Council of humans (hard-capped at a maximum of 21 members to ensure agile coordination). Any protocol action, parameter change, or software update now requires a mathematically enforced supermajority of Council signatures.

### 3. Permissionless (Absolute Decentralization)

In `permissionless` mode, all governance actions are unilaterally rejected by the network. The protocol becomes completely immutable, relying strictly on "Code is Law". No central authority or council has the power to grant premium names, push OTA updates, or rotate keys. Network upgrades can only be executed via community-driven hard forks.

In Phase 2, the network matures into a distributed republic. It is governed by a globally distributed Council of humans (hard-capped at a maximum of 21 members to ensure agile coordination). Any protocol action, parameter change, or software update now requires a mathematically enforced supermajority of Council signatures.

### The Thresholds (Council Mode)
The thresholds are hardcoded in the rust binaries and cannot be bypassed without a hard fork:
- **69% Supermajority:** Required to push an OTA software update, adjust VDF cost parameters, or add/remove a Council member.
- **90% Supermajority:** Required to forcibly seize or reassign a "premium" or highly contested namespace (e.g., if a trademark dispute threatens the network, or if a botnet is using a `.kin` domain for malware). This extremely high bar prevents the council from easily stealing names from legitimate users.
- **95% Supermajority:** Required to execute a catastrophic key rotation (e.g., if a nation-state compromises multiple council members and the remaining members must coordinate a massive reset).

### The 48-Hour OTA Timelock and the Social Failsafe

Even with these thresholds, what happens if 69% of the Council is compromised simultaneously and attempts to push malicious malware as an OTA update to all Kinetic nodes?

To protect against total Council capture, the protocol enforces an `OTA_TIMELOCK_SECONDS` of exactly 48 hours for any proposed software update.

Once the malicious update is signed by a 69% supermajority, the network recognizes the signatures as valid but absolutely refuses to execute the binary replacement for 48 hours. 

During this critical window, the proposed binary hash and its contents are publicly visible on the DHT. Security researchers, community members, and node operators can inspect the payload. If the community determines the Council has gone rogue, 48 hours is enough time for users to socially coordinate off-band (via Twitter, Discord, GitHub), hard-fork the `kinetic-network` open-source crate, strip the malicious Council of their keys in the genesis state, and restart the network.

This elegant mechanism ensures that the Council has the agility to patch bugs, but the ultimate power remains exactly where it belongs: with the users' ability to reject malicious consensus.
