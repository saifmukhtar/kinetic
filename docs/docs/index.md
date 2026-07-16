---
layout: home

hero:
  name: "Kinetic"
  text: "The Sovereign Namespace Engine"
  tagline: "Deploy your own cryptographically secured naming network in minutes. Or use the public .kin network — no fees, no ICANN, no blockchain."
  actions:
    - theme: brand
      text: Fork Your Own Network
      link: /forking
    - theme: alt
      text: Get Started with .kin
      link: /getting_started
    - theme: alt
      text: View on GitHub
      link: https://github.com/saifmukhtar/kinetic

features:
  - title: "🍴 Fully Forkable"
    details: "Any university, company, or community can deploy their own sovereign namespace with a single config file. Change the TLD, difficulty, and bootstrap nodes — compile and ship."
  - title: "🔐 Zero Fees. Zero Gas. Zero ICANN."
    details: "Names are secured by Verifiable Delay Functions — un-parallelizable sequential computation. No recurring fees. No token. No central authority."
  - title: "🔄 Swappable Engines"
    details: "VdfEngine and StorageEngine are abstract Rust traits. Swap Chia's chiavdf for any VDF construction. Swap Sled for RocksDB, SQLite, or a distributed store."
  - title: "🛡️ Squatter-Proof by Design"
    details: "A 2-character name takes 5 months of continuous CPU. Mass dictionary squatting is physically impossible at scale — not just economically discouraged."
  - title: "🌐 Transparent Browser Integration"
    details: "OS-level Split-DNS loopback intercepts your TLD queries. Browsers see a standard DNS response. No extensions. No configuration. No breakage of legacy traffic."
  - title: "⚡ Epoch-Bound DoS Resistance"
    details: "kinetic-host rotates its libp2p transport identity every drand pulse (3 seconds). Attackers targeting the transport layer are invalidated before their packets land."
---

<CardGrid>
  <FeatureCard title="Fork in 10 Minutes" icon="CodeBracketIcon">
    Run `kinetic-forge`, answer a few questions about your TLD and hardware, and walk away with a fully compiled network binary suite. No Rust expertise required.
  </FeatureCard>
  <FeatureCard title="Identity-Centric Architecture" icon="FingerPrintIcon">
    Names resolve to permanent KID identity documents — not IP addresses. Ownership changes never compromise identity. Capability Manifests declare services, not locations.
  </FeatureCard>
  <FeatureCard title="The .kin Public Network" icon="GlobeAltIcon">
    The canonical reference deployment. Permissionless, leaderless, and globally distributed. No operator can reset it. No government can seize it. Only math governs it.
  </FeatureCard>
</CardGrid>
