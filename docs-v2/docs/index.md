---
layout: home

hero:
  name: "Kinetic"
  text: "The Gasless Naming Network"
  tagline: "Infrastructure you can run without permission, modify without approval, and abandon without loss."
  actions:
    - theme: brand
      text: Get Started
      link: /components-demo
    - theme: alt
      text: View on GitHub
      link: https://github.com/saif/kinetic

features:
  - title: Zero Fees. Zero Gas.
    details: Instant, free domain registrations secured by Verifiable Delay Functions (VDFs) instead of expensive blockchains.
  - title: Local-First Architecture
    details: The Kinetic Daemon runs locally on your machine, exposing a simple REST API for your applications.
  - title: Sybil Resistant
    details: Mathematical time-locks ensure that squatters and bots cannot hoard names without incurring massive computational costs.
---

<CardGrid>
  <FeatureCard title="Decentralized Identity" icon="FingerPrintIcon">
    Own your digital identity without relying on a centralized registrar. Names are mapped securely on the DHT.
  </FeatureCard>
  <FeatureCard title="Kinetic Drop" icon="PaperAirplaneIcon">
    Share files securely and privately with other `.kin` users, fully encrypted over libp2p.
  </FeatureCard>
  <FeatureCard title="Developer SDK" icon="CodeBracketIcon">
    No need to understand Kademlia or VDFs. Just hook your app into the local REST API and start building.
  </FeatureCard>
</CardGrid>
