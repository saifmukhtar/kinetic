# VDF Hardware Calibration

This document outlines the hardware baseline assumptions used to calibrate the Proof-of-Patience delay curves in `kinetic-core`.

## The Problem with "Wall-Clock Time"
Verifiable Delay Functions (VDFs) are measured in **iterations** (squarings), not seconds. The amount of real-world "wall-clock time" it takes to compute $N$ iterations depends entirely on the speed of the hardware evaluating the VDF.

Therefore, when the codebase or whitepaper says "a 6-character name takes 8 hours," that statement is inherently tied to a specific hardware generation.

## The 2025/2026 Baseline
Our current scaling coefficients (implemented in `calculate_required_iterations` in `kinetic-core/src/types.rs`) are pinned to the following baseline assumption:
- **Baseline Speed:** ~300,000 iterations per second (ips).
- **Target Hardware:** A mid-range, single-core consumer CPU available in 2025/2026 (e.g., Apple M2/M3 efficiency core, or an equivalent AMD/Intel core).
- **Algorithm:** Repeated squaring in ideal class groups of unknown order (via the `chiavdf` Rust bindings).

At exactly 300k ips, the base iterations by name length are:
- `3,000,000` iterations (16+ chars) ≈ 10 seconds
- `12,000,000` iterations (9–15 chars) ≈ 40 seconds
- `36,000,000` iterations (5–8 chars) ≈ 2 minutes
- `144,000,000` iterations (4 chars) ≈ 8 minutes
- `540,000,000` iterations (3 chars) ≈ 30 minutes
- `2,160,000,000` iterations (2 chars) ≈ 2 hours
- `8,640,000,000` iterations (1 char) ≈ 8 hours

## Moore's Law & Future Scaling
To prevent the cost floor from collapsing over time due to Moore's law or specialized ASICs, `kinetic-core` currently applies a linear offset based on the current Drand round (`current_drand_round`). 

Because Drand emits a pulse every 30 seconds, a ~1% increase is added per 12-hour epoch (1440 rounds) to the base difficulty. This keeps the cost of registering names aligned with hardware improvements.

> **Note to Future Maintainers:** If specialized VDF ASICs become cheap and widely available, the 300k ips baseline will break. If commodity ASICs push the baseline to 30M ips, the base iteration costs will need to be revised by a factor of 100x via a hard fork to maintain the same wall-clock delays.
