---
layout: home

hero:
  name: "Kinetic"
  text: "The Sovereign Namespace Engine"
  tagline: "Register names secured by math, not money. Deploy your own naming network in minutes."
  actions:
    - theme: brand
      text: I'm a User →
      link: /users/
    - theme: alt
      text: I'm a Developer →
      link: /developers/
    - theme: alt
      text: Fork the Engine →
      link: /operators/
    - theme: alt
      text: How It Works →
      link: /architecture/01-philosophy

features:
  - icon: 🌐
    title: For Users
    details: "Register a .kin name from your terminal in 30 minutes. No account. No credit card. No corporation in the middle. Your name is secured by cryptographic proof stored across a global network."
    link: /users/
    linkText: Get started →

  - icon: 🛠️
    title: For Developers
    details: "Build applications on top of Kinetic using the REST API or the TypeScript and Rust SDKs. Resolve names, register programmatically, publish DNS zones — all from your code."
    link: /developers/
    linkText: Read the API docs →

  - icon: 🍴
    title: Fork the Engine
    details: "Any university, company, or community can deploy their own sovereign namespace. Configure one file, run kinetic-forge, and walk away with your own TLD and governance keys."
    link: /operators/
    linkText: Learn how →

  - icon: 🔬
    title: How Kinetic Works
    details: "A 10-chapter architectural deep dive into VDFs, Immunological DHT, Split-DNS routing, KID identity, governance, and the full threat model. For engineers who want to understand every layer."
    link: /architecture/01-philosophy
    linkText: Read the series →
---

<div class="home-details">

## Why Kinetic?

Every previous attempt at decentralized naming made the same mistake: replacing one gatekeeper with another.

- **Legacy DNS** → Corporate and government control. Names can be seized with a phone call.
- **Crypto naming (ENS, Unstoppable)** → Capital replaces authority. Wealthy speculators hoard short names.
- **Proof of Personhood** → Biometric surveillance replaces money. One name per body, forever.

**Kinetic uses a different friction mechanism: computational time.**

A [Verifiable Delay Function (VDF)](/cryptography) is a mathematical puzzle that takes a provably specific amount of time to solve and cannot be parallelized. A billionaire with 10,000 servers cannot register a name faster than a developer on a laptop. Mass squatting is physically impossible, not just economically discouraged.

| Name Length | Registration Time | Cost |
|---|---|---|
| 8+ characters | ~2 hours | $0 |
| 6 characters | ~12 hours | $0 |
| 4 characters | ~15 days | $0 |
| 2 characters | ~5 months | $0 |

**One CPU. Zero dollars. Permanent ownership secured by math.**

</div>

<div class="home-architecture">

## Understand the Engine

<div class="arch-grid">

<a class="arch-card" href="/architecture/01-philosophy">
  <span class="arch-num">01</span>
  <span class="arch-title">Philosophy</span>
  <span class="arch-desc">Why not a blockchain? The stateless, local-first architecture.</span>
</a>

<a class="arch-card" href="/architecture/02-cryptography-and-identity">
  <span class="arch-num">02</span>
  <span class="arch-title">Cryptography & Identity</span>
  <span class="arch-desc">Ed25519, post-quantum readiness, and the KID identity layer.</span>
</a>

<a class="arch-card" href="/architecture/03-vdf-and-cost">
  <span class="arch-num">03</span>
  <span class="arch-title">VDF & Cost</span>
  <span class="arch-desc">Replacing money with time — how squatting becomes physically impossible.</span>
</a>

<a class="arch-card" href="/architecture/04-network-routing">
  <span class="arch-num">04</span>
  <span class="arch-title">Network Routing</span>
  <span class="arch-desc">libp2p, Kademlia DHT, and Sybil resistance at the routing layer.</span>
</a>

<a class="arch-card" href="/architecture/05-storage-engine">
  <span class="arch-num">05</span>
  <span class="arch-title">Storage Engine</span>
  <span class="arch-desc">Sled, RocksDB, and the swappable StorageEngine trait.</span>
</a>

<a class="arch-card" href="/architecture/06-daemon-and-dns">
  <span class="arch-num">06</span>
  <span class="arch-title">Daemon & DNS</span>
  <span class="arch-desc">How kinetic-daemon bridges the legacy web and the P2P network.</span>
</a>

<a class="arch-card" href="/architecture/07-governance">
  <span class="arch-num">07</span>
  <span class="arch-title">Governance</span>
  <span class="arch-desc">Bicameral upgrade keys, council multisig, and code-as-law modes.</span>
</a>

<a class="arch-card" href="/architecture/08-client-architecture">
  <span class="arch-num">08</span>
  <span class="arch-title">Client Architecture</span>
  <span class="arch-desc">Desktop app, mobile light clients, and the untrusted gateway model.</span>
</a>

<a class="arch-card" href="/architecture/09-forks-and-compilation">
  <span class="arch-num">09</span>
  <span class="arch-title">Forks & Compilation</span>
  <span class="arch-desc">network.json, build.rs constants, and swappable engine traits.</span>
</a>

<a class="arch-card" href="/architecture/10-threat-and-trust-model">
  <span class="arch-num">10</span>
  <span class="arch-title">Threat & Trust Model</span>
  <span class="arch-desc">What Kinetic assumes, what it defends against, and what's out of scope.</span>
</a>

</div>

<div class="arch-cta">
  <a href="/architecture/01-philosophy" class="arch-btn">Start reading →</a>
</div>

</div>

<style>
/* ── Why Kinetic ──────────────────────────────────────────── */
.home-details {
  max-width: 860px;
  margin: 5rem auto 0;
  padding: 0 1.5rem;
}

.home-details h2 {
  font-family: 'Instrument Serif', Georgia, serif;
  font-style: italic;
  font-weight: 400;
  font-size: 2rem;
  letter-spacing: -0.02em;
  color: var(--vp-c-text-1);
  margin-bottom: 1.25rem;
}

.home-details p,
.home-details li {
  color: var(--vp-c-text-2);
  line-height: 1.75;
  font-size: 0.9375rem;
}

.home-details table {
  width: 100%;
  border-collapse: collapse;
  margin: 1.75rem 0;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  overflow: hidden;
  font-size: 0.875rem;
}

.home-details th {
  background: var(--vp-c-bg-soft);
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  font-weight: 500;
  padding: 0.65rem 1rem;
  border-bottom: 1px solid var(--vp-c-divider);
  text-align: left;
  color: var(--vp-c-text-1);
}

.home-details td {
  padding: 0.6rem 1rem;
  border-bottom: 1px solid var(--vp-c-divider);
  color: var(--vp-c-text-2);
}

.home-details tr:last-child td {
  border-bottom: none;
}

/* ── Feature cards: force 2×2 compact grid ───────────────── */
.VPFeatures .items {
  display: grid !important;
  grid-template-columns: repeat(2, 1fr) !important;
  gap: 0.75rem !important;
}

@media (max-width: 768px) {
  .VPFeatures .items {
    grid-template-columns: 1fr !important;
  }
}

/* Compact the VPFeature card itself */
.VPFeatures .item {
  width: 100% !important;
  max-width: 100% !important;
  padding: 0 !important;
}

.VPFeature {
  padding: 0.875rem 1rem !important;
}

.VPFeature .box {
  padding: 0 !important;
  gap: 0.375rem !important;
}

.VPFeature .icon {
  font-size: 1.25rem !important;
  margin-bottom: 0.25rem !important;
  width: 32px !important;
  height: 32px !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
}

.VPFeature .title {
  font-size: 0.9375rem !important;
  font-weight: 700 !important;
  letter-spacing: -0.02em !important;
  line-height: 1.2 !important;
  margin: 0 !important;
  color: var(--vp-c-text-1) !important;
}

.VPFeature .details {
  font-size: 0.8rem !important;
  line-height: 1.55 !important;
  color: var(--vp-c-text-2) !important;
  margin: 0 !important;
}

.VPFeature .link-text {
  font-size: 0.8rem !important;
  margin-top: 0.375rem !important;
}


/* ── Architecture Section ─────────────────────────────────── */
.home-architecture {
  max-width: 1100px;
  margin: 5rem auto 6rem;
  padding: 0 1.5rem;
}

.home-architecture h2 {
  font-family: 'Instrument Serif', Georgia, serif;
  font-style: italic;
  font-weight: 400;
  font-size: 2rem;
  letter-spacing: -0.02em;
  color: var(--vp-c-text-1);
  margin-bottom: 2rem;
}

/* Grid of 10 chapter cards */
.arch-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 0.5rem;
  margin-bottom: 2rem;
}

.arch-card {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
  padding: 0.625rem 0.875rem;
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
  border-radius: 5px;
  text-decoration: none !important;
  box-shadow: 2px 3px 0px rgba(26, 23, 20, 0.08);
  transition:
    transform 200ms cubic-bezier(0.34, 1.56, 0.64, 1),
    box-shadow 200ms cubic-bezier(0.34, 1.56, 0.64, 1),
    border-color 120ms ease;
}

.arch-card:hover {
  transform: translate(-2px, -2px);
  box-shadow: 5px 6px 0px rgba(26, 23, 20, 0.16);
  border-color: var(--vp-c-brand-1) !important;
  text-decoration: none !important;
}

.arch-num {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.625rem;
  font-weight: 500;
  letter-spacing: 0.08em;
  color: var(--vp-c-brand-1);
}

.arch-title {
  font-family: 'Inter', sans-serif;
  font-weight: 600;
  font-size: 0.8125rem;
  letter-spacing: -0.02em;
  color: var(--vp-c-text-1);
  line-height: 1.25;
}

/* Hide description — keeps cards compact */
.arch-desc {
  display: none;
}

/* CTA below the grid */
.arch-cta {
  text-align: center;
}

.arch-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
  padding: 0.625rem 1.5rem;
  font-family: 'Inter', sans-serif;
  font-size: 0.875rem;
  font-weight: 600;
  letter-spacing: 0.01em;
  color: var(--vp-c-text-1) !important;
  background: transparent;
  border: 1.5px solid var(--vp-c-divider);
  border-radius: 4px;
  text-decoration: none !important;
  box-shadow: 3px 4px 0px rgba(26, 23, 20, 0.10);
  transition:
    transform 220ms cubic-bezier(0.34, 1.56, 0.64, 1),
    box-shadow 220ms cubic-bezier(0.34, 1.56, 0.64, 1),
    border-color 120ms ease,
    color 120ms ease;
}

.arch-btn:hover {
  color: var(--vp-c-brand-1) !important;
  border-color: var(--vp-c-brand-1);
  transform: translate(-1px, -1px);
  box-shadow: 5px 6px 0px rgba(26, 23, 20, 0.14);
  text-decoration: none !important;
}

/* Dark mode adjustments */
.dark .arch-card {
  box-shadow: 3px 4px 0px rgba(0, 0, 0, 0.30);
}

.dark .arch-card:hover {
  box-shadow: 5px 6px 0px rgba(0, 0, 0, 0.40);
}

.dark .arch-btn {
  box-shadow: 3px 4px 0px rgba(0, 0, 0, 0.30);
}

.dark .arch-btn:hover {
  box-shadow: 5px 6px 0px rgba(0, 0, 0, 0.40);
}

/* ── Responsive ───────────────────────────────────────────── */
@media (max-width: 640px) {
  .arch-grid {
    grid-template-columns: 1fr 1fr;
  }

  .home-details,
  .home-architecture {
    padding: 0 1rem;
  }
}

@media (max-width: 400px) {
  .arch-grid {
    grid-template-columns: 1fr;
  }
}
</style>
