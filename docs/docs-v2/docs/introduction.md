# Introduction

*A sovereign namespace engine secured purely by math and time.*
*Created by [Saif Mukhtar](https://saifmukhtar.dev)*

> **Official IETF Internet-Drafts:**
> - [draft-mukhtar-kinetic-network-00](https://www.ietf.org/archive/id/draft-mukhtar-kinetic-network-00.html)
> - [draft-mukhtar-kinetic-identity-00](https://www.ietf.org/archive/id/draft-mukhtar-kinetic-identity-00.html)

---

## What Kinetic Actually Is

Kinetic is not a domain registrar. It is not a blockchain. It is not another `.eth` or `.crypto`.

**Kinetic is an open-source namespace engine** — a Rust binary suite that any university, company, government, or community can deploy to run their own cryptographically secured naming network. You configure one file (`network.json`), run `kinetic-forge`, and walk away with a complete, self-contained network with your own TLD, your own bootstrap nodes, and your own governance keys.

The canonical public deployment of this engine is the **`.kin` network** — a permissionless global commons where no single entity holds administrative authority. `.kin` is the proof that the engine works without any operator at all.

**Two ways to use Kinetic:**

| | Fork Your Own Network | Use the `.kin` Network |
|---|---|---|
| **Who** | Universities, companies, governments, communities | Developers, open-source builders, privacy advocates |
| **TLD** | Whatever you configure (`.uni`, `.acme`, `.internal`) | `.kin` |
| **Control** | You hold the governance keys. You can reset. | No operator. Math governs it. |
| **Squatters** | VDF cliff + you can restart the network | VDF cliff alone |
| **Entry point** | [`kinetic-forge`](./forking.md) | [`Getting Started`](./getting_started.md) |

---

## Choose Your Path

### 🍴 I want to deploy my own network
→ Start with **[Fork Your Own Network](./forking.md)**

This covers `kinetic-forge`, `network.json`, swappable `VdfEngine` and `StorageEngine` backends, bootstrap node setup, and the fork squatter economics that make private networks self-defending.

### 🌐 I want to register a `.kin` name
→ Start with **[Getting Started](./getting_started.md)**

This covers installing the daemon, the two-phase commit/reveal registration, configuring your Capability Manifest, and keeping your name alive with the heartbeat system.

### 🔐 I want to understand the cryptography
→ Start with **[The Mathematical Engine](./cryptography.md)**

This covers VDFs over Class Groups, the Wesolowski proof protocol, the `drand` Quicknet beacon, and Ed25519 identity binding. No prior cryptography knowledge assumed.

### 📡 I want to run infrastructure or contribute
→ Start with **[Network Architecture](./network_architecture.md)**

This covers the Immunological DHT, Redundant Deterministic Storage, Competitive Gossip validation, and the `kinetic-node` headless infrastructure binary.

---

## Why This Had to Be Built

To understand why Kinetic exists, you need to understand what every previous attempt at decentralized naming got wrong. The problem is older and harder than it looks.

### The Mathematical Constraint: Zooko's Triangle

In 2001, Zooko Wilcox-O'Hearn formalized a trilemma that had been haunting network engineers for decades. Any naming system can have at most two of three properties simultaneously:

1. **Human-Meaningful** — Names that humans can read, remember, and type (`apple`, `university`, `example`)
2. **Decentralized** — No central authority controls the namespace
3. **Secure** — The system resists spoofing and Sybil attacks

Every approach for the past four decades has failed to achieve all three without introducing a new fatal flaw.

---

### Era 1: ICANN and Absolute Centralization (1980s — Present)

The legacy DNS deliberately sacrifices the **Decentralized** leg. It achieves human-meaningful names and security through absolute hierarchical centralization.

At the top sits ICANN — the Internet Corporation for Assigned Names and Numbers. ICANN has unchecked authority to create TLDs and delegate them to registries. Registries delegate to registrars. Registrars sell to you.

**The consequences:**

- **Political seizure:** A single phone call can compel ICANN to revoke a domain. No cryptographic due process exists. State actors and corporations exercise this power routinely.
- **Monopoly rent extraction:** Verisign holds an artificial monopoly over `.com`. They charge arbitrary annual fees for a database entry that costs fractions of a cent to maintain. The fee is not a service cost — it is a toll.
- **Speculative markets:** Because names are artificially scarce and monetarily valued, an entire predatory industry emerged — domain parking, aftermarket speculation, cybersquatting — that extracts value from builders while producing nothing.

Legacy DNS is technically functional and deeply unethical. It is digital feudalism: developers lease land from a central sovereign.

---

### Era 2: Capital-Gated Blockchains (2017 — Present)

Blockchain naming systems (ENS, Handshake, Unstoppable Domains) placed the registry on a decentralized ledger — achieving the **Decentralized** leg. But they immediately confronted the Sybil problem.

In a permissionless network, generating a request costs effectively nothing. Without a gating mechanism, a single attacker can claim every word in the English dictionary in seconds. So blockchain naming systems instituted a gating function: **Financial Capital**.

**The consequences:**

- **Digital landlordism, decentralized edition:** Capital-gated registries favor entities with deep financial liquidity. Wealthy speculators hoard short names and extract rent from legitimate builders — exactly the same dynamic as ICANN, just with fewer regulations.
- **Developer pricing-out:** A peer-to-peer routing primitive should not require a perpetual subscription fee. Tying infrastructure to cryptocurrency market prices makes development costs unpredictable and inaccessible in developing economies.
- **Valuation paradox:** When the underlying token spikes during a bull market, renewal costs spike with it. Names become inaccessible to the people who need them most precisely when the ecosystem is most active.

Capital-gated registries did not solve digital landlordism. They democratized the ability to be the landlord.

---

### Era 3: Proof of Personhood (2020 — Present)

To eliminate capital requirements entirely, some protocols defined the friction mechanism as **physical human uniqueness** — one human, one name.

Proof of Personhood systems (Worldcoin, BrightID, Proof of Humanity) prevent Sybil attacks by ensuring an attacker cannot generate a million identities without a million physical bodies.

**The consequences:**

- **Extreme onboarding friction:** Retina scans, synchronous video ceremonies, NFC passport reads, scheduled verification epochs. A developer cannot spin up an ephemeral staging domain at 2 AM if they need to scan their iris first.
- **Privacy destruction:** Extracting unique physical identity — even with zero-knowledge proofs — almost always shackles the system to government-issued credentials or biometric hardware. Pseudonymity is sacrificed.
- **The multiple-alias reality:** Developers legitimately need multiple names — production, staging, personal, anonymous, testing. A strict 1:1 mapping between a human body and a network handle is an artificial constraint that fundamentally misunderstands how infrastructure is deployed.

---

### The Kinetic Solution: Computational Time as Friction

We are left with an architectural impasse. A truly decentralized namespace cannot survive without friction. But:

- Friction as **central authority** → censorship and seizure
- Friction as **money** → digital landlordism
- Friction as **identity** → onboarding destruction and privacy loss

**Kinetic abandons all three.**

The cost of namespace acquisition is defined strictly as **un-parallelizable sequential computation and time** — returning to the purest form of permissionless security.

A Verifiable Delay Function (VDF) is a mathematical puzzle that:
- Takes a provably specific amount of time to solve
- **Cannot be parallelized** — a billionaire with 10,000 ASICs cannot solve a single VDF faster than a hobbyist on a laptop
- Produces a compact cryptographic proof that anyone can verify in milliseconds

Kinetic uses VDFs to make squatting computationally ruinous:

| Name Length | Required Computation | Time on Modern CPU |
|---|---|---|
| 1 character | × 1,753,200 baseline | ~100 years |
| 2 characters | × 7,200 baseline | ~5 months |
| 4 characters | × 720 baseline | ~15 days |
| 6 characters | × 24 baseline | ~12 hours |
| 8+ characters | × 4 baseline | ~2 hours |
| 21+ characters | × 1 baseline | ~30 minutes |

Mass dictionary squatting is not just expensive — it is physically impossible at scale. A single CPU cannot process more than a handful of names per year at the 6-character tier. An attacker with a thousand CPUs still cannot claim a thousand 6-character names in any reasonable timeframe.

For a single legitimate developer registering one name: **30 minutes of CPU, zero dollars, zero accounts, zero approvals.**

---

## The Engine Philosophy

The deepest insight behind Kinetic is that the `.kin` network — the public canonical deployment — is not the product.

**The engine is the product.**

Every organization that forks Kinetic becomes a stakeholder in the engine's quality and security. Every university running `.uni`, every company running `.internal`, every open-source community running their own TLD — they all benefit from improvements to the shared cryptographic core, and they all contribute to the network effect that makes the engine trustworthy.

`.kin` is the proof that the engine works without any operator. The forks are the proof that the engine works for everyone.

Welcome to the Kinetic Protocol.
