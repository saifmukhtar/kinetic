---
layout: home

hero:
  name: "Kinetic"
  text: "The Sovereign Namespace Engine"
  tagline: "Register names secured by math, not money. Deploy your own naming network in minutes. No fees. No central authority. No global ledger."
  actions:
    - theme: brand
      text: I'm a User →
      link: /users/
    - theme: alt
      text: I'm a Developer →
      link: /developers/
    - theme: alt
      text: Fork the Engine →
      link: /forking

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
    link: /forking
    linkText: Learn how →
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

<style>
.home-details {
  max-width: 960px;
  margin: 4rem auto;
  padding: 0 1.5rem;
}

.home-details h2 {
  font-size: 1.8rem;
  margin-bottom: 1rem;
}

.home-details table {
  width: 100%;
  border-collapse: collapse;
  margin: 1.5rem 0;
}

.home-details th,
.home-details td {
  padding: 0.6rem 1rem;
  border: 1px solid var(--vp-c-divider);
  text-align: left;
}

.home-details th {
  background: var(--vp-c-bg-soft);
  font-weight: 600;
}
</style>
