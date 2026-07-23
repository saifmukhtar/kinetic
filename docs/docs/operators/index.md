---
title: Fork Operators — Deploy Your Own Network
---

# Fork Operators

*Deploy a sovereign namespace under your own TLD — for universities, companies, governments, and communities.*

Kinetic is not a single product. It is an **engine**. Any organization can take the same cryptographic core that powers `.kin` and deploy their own fully independent naming network, with their own TLD, their own governance keys, and their own rules.

---

## What You Can Deploy

| Fork Type | Use Case |
|---|---|
| **University namespace** | `.uni` — internal student/faculty identity, no fees, no squatters |
| **Corporate service discovery** | `.internal` — replace DNS-based service discovery with VDF-secured names |
| **Government public services** | A sovereign TLD under your jurisdiction, mathematically secure |
| **Developer sandbox** | Fast, cheap, throwaway — configure a low-difficulty test network in minutes |
| **Research fork** | Swap out the VDF or storage engine for academic study |

---

## The Three Steps

1. **Run `kinetic-forge`** — the interactive wizard generates your `network.json` in under 5 minutes
2. **Compile your binaries** — all nodes share identical cryptographic constants baked in at build time
3. **Launch bootstrap nodes** — two stable servers are all you need to start

→ **[Deploy with kinetic-forge](/forking)**

---

## How It Works

Every fork inherits the full Kinetic protocol:

- **VDF-based registration** — squatting is computationally ruinous regardless of TLD
- **Redundant Deterministic Storage** — Eclipse attacks are statistically impossible at M=32
- **Split-DNS loopback** — your TLD resolves natively in any browser, no plugins required
- **Swappable engines** — replace the VDF, storage, or governance backend at compile time
- **Operator sovereignty** — if squatting becomes a problem, restart the network and wipe all registrations

→ **[Continue reading: Deploy with kinetic-forge](/forking)**
