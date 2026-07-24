---
title: VDF Hardware Calibration
prev:
  text: 'Deploy with kinetic-forge'
  link: '/forking'
next:
  text: 'Simulation Sandbox'
  link: '/kinetic_sim'
---

# VDF Hardware Calibration

This document outlines the hardware baseline assumptions used to calibrate the Proof-of-Patience delay curves in `kinetic-core`.

## The Problem with "Wall-Clock Time"
Verifiable Delay Functions (VDFs) are measured in **iterations** (squarings), not seconds. The amount of real-world "wall-clock time" it takes to compute $N$ iterations depends entirely on the speed of the hardware evaluating the VDF.

Therefore, when the codebase or whitepaper says "a 21-character name takes 30 minutes," that statement is inherently tied to a specific hardware generation.

## The Calibration Baseline
Our current scaling coefficients (implemented in `calculate_required_iterations` in `kinetic-core/src/consensus_math.rs`) are pinned to a benchmark base iteration count of **238,819,830**, which represents approximately 30 minutes of compute time. 
- **Baseline Speed:** ~132,000 iterations per second (ips).
- **Target Hardware:** A standard consumer CPU core (e.g., Apple Silicon efficiency core, or an equivalent AMD/Intel core).
- **Algorithm:** Repeated squaring in ideal class groups of unknown order (via the `chiavdf` Rust bindings).

Based on this, the required iterations and their estimated wall-clock times are defined on a steep "Squatter Cliff" curve:

- **0–1 chars:** Reserved/Impossible (100 years / ~418 trillion iterations)
- **2 chars:** 5 months (~1.71 trillion iterations)
- **3 chars:** 3 months (~1.03 trillion iterations)
- **4 chars:** 15 days (~171 billion iterations)
- **5 chars:** 1 day (~11.4 billion iterations)
- **6 chars:** 12 hours (~5.7 billion iterations)
- **7 chars:** 2.5 hours (~1.19 billion iterations)
- **8–10 chars:** 2 hours (~955 million iterations)
- **11–17 chars:** 1.5 hours (~716 million iterations)
- **18–20 chars:** 1 hour (~477 million iterations)
- **21–62 chars:** 30 minutes (238,819,830 iterations - Baseline)

### The "Jackpot" Length (63 Characters)
If a user registers a maximum-length 63-character name, the VDF iteration requirement is determined probabilistically by hashing the name itself along with the current Drand round. Depending on the first two numeric digits of the SHA-256 hash, the wait time scales exponentially:
- `63`: 63 Seconds (Jackpot!)
- `00–10`: 63 Minutes
- `11–20`: 63 Hours
- `21–30`: 63 Days
- `...`
- Up to **63 Millennia** for the worst hash rolls.

## Moore's Law & Future Scaling
Because hardware improves over time (Moore's law, ASICs, FPGAs), a static iteration count will eventually lead to wait times dropping significantly. 

> **Note to Future Maintainers:** The `BENCHMARK_BASE_ITERATIONS` constant is generated via `network.json`. If specialized VDF ASICs become cheap and widely available, the 132k ips baseline will break. To maintain the targeted "wall-clock delays," `BENCHMARK_BASE_ITERATIONS` will need to be revised upward via a hard fork network upgrade.
