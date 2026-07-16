# Component Library Demo

This page demonstrates the custom interactive components we built specifically for the Kinetic documentation, inspired by WebMCP, Manim, SmartConnections, and Radicle.

## 1. Feature Cards (WebMCP Style)
Use these to highlight features. They use glassmorphism and `@heroicons`.

<CardGrid>
  <FeatureCard title="Lightning Fast" icon="BoltIcon">
    Runs locally on your machine with millisecond response times.
  </FeatureCard>
  <FeatureCard title="Secure by Default" icon="ShieldCheckIcon">
    Fully encrypted, mathematically secured identity via VDFs.
  </FeatureCard>
</CardGrid>

## 2. Terminal Window (Radicle Style)
Use this to show CLI commands exactly as they would appear in a macOS terminal.

<TerminalWindow title="kinetic-daemon">

```bash
$ kinetic start --port 8080
[INFO] Booting Kinetic Daemon...
[INFO] Generating VDF Proof (Difficulty: 100000)...
[SUCCESS] Daemon running on 127.0.0.1:8080
```

</TerminalWindow>

## 3. Step-by-Step UI (SmartConnections Style)
Use this for tutorials and "Getting Started" guides.

<Steps>
  <Step title="Install the Daemon">
    First, download the Kinetic binary for your system and place it in your path.
  </Step>
  <Step title="Start the Network">
    Run `kinetic start` to boot your local Kademlia node and join the DHT.
  </Step>
  <Step title="Register a Name">
    Run `kinetic register [name]` to compute the VDF and broadcast your identity.
  </Step>
</Steps>

## 4. FAQ Accordions (WebMCP Style)

<FaqAccordion question="Does Kinetic use global ledgers?">
No. Kinetic is entirely ledger-free. It uses a Kademlia Distributed Hash Table (DHT) and Verifiable Delay Functions (VDFs) to prevent spam without requiring a global ledger or transaction fees.
</FaqAccordion>

<FaqAccordion question="What happens if I go offline?">
Because the network is designed for personal laptops, you are allowed to go offline. Your identity is secured by a Proof-of-Storage "Tamper Seal" that ensures you are maintaining your quota even while asleep.
</FaqAccordion>

## 5. Admonitions & Code Groups (Manim Style)
These are native to VitePress but have been styled to match our premium aesthetic.

::: warning IMPORTANT
You must ensure the Kinetic Daemon is running before making any local API calls.
:::

::: code-group

```js [Node.js]
const response = await fetch('http://127.0.0.1:8080/resolve/saif.kin');
const data = await response.json();
```

```python [Python]
import requests
response = requests.get('http://127.0.0.1:8080/resolve/saif.kin')
data = response.json()
```

```rust [Rust]
let response = reqwest::get("http://127.0.0.1:8080/resolve/saif.kin").await?;
let data: Value = response.json().await?;
```

:::
