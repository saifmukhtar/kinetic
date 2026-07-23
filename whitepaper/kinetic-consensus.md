# Technical Paper I: Core Consensus & Proof of Patience

**Author:** Saif Mukhtar
**Date:** July 2026
**Version:** 2.0.0

## Abstract

This paper defines the core cryptographic and mathematical consensus mechanisms of the Kinetic Protocol. To achieve a globally sovereign namespace without a centralized ledger or monetary fees, the protocol utilizes a strictly sequential, three-phase cryptographic lifecycle. By combining Verifiable Delay Functions (VDFs) computed over Class Groups of Imaginary Quadratic Fields with the `drand` Quicknet distributed randomness beacon (3-second pulse interval), Kinetic neutralizes front-running, dictionary squatting, and dead-state hoarding via an algorithmic Proof of Patience.

This paper documents the consensus mathematics as they exist in the live codebase (`kinetic-core/src/consensus_math.rs`). All constants referenced here are sourced from `network.json` and compiled into the binary at build time via `kinetic-core/build.rs`. Fork operators who deploy their own network may freely adjust these constants to match their hardware baseline and squatter-resistance requirements.

---

## 1. Introduction

In a public, permissionless registry, transmitting a plaintext name claim exposes the client to front-running. A sniper bot can observe the request in the network mempool and duplicate it with higher network priority. Legacy systems resolve this via financial bidding wars. Kinetic introduces a **Proof of Patience** instead — registering a name requires a provable expenditure of un-parallelizable sequential time, rendering automated sniping algorithms computationally blind.

---

## 2. Phase I: Clockless Front-Running Neutralization

Kinetic neutralizes front-running via Sequential VDF Linking anchored to the `drand` Quicknet beacon [1], which emits a cryptographically verifiable random pulse every **3 seconds**.

Let $S$ be the set of valid human-readable strings, and let $n \in S$ be the target name.

1. **Commitment Generation:** The client generates a high-entropy salt $s \in \{0,1\}^{256}$ and fetches the latest `drand` pulse $B_{t_1}$. The client cryptographically binds their public key into the hash commitment:
   $$ C = H(n \parallel s \parallel B_{t_1} \parallel \text{PubKey}) $$
2. **Sequential Linking:** The client uses $C$ as the base seed input for a massive Verifiable Delay Function (VDF) computation requiring $T$ iterations to evaluate.
3. **The Reveal:** Upon VDF completion, the client broadcasts the plaintext tuple $(n, s, B_{t_1}, \text{VDF}_{\text{proof}})$.

Because $B_{t_1}$ is unpredictable at commitment time, the VDF cannot be pre-computed. Because the VDF inherently requires $T$ sequential iterations, its completion mathematically proves that the commitment $C$ existed before computation began. Because $C$ embeds the original $\text{PubKey}$, a sniper cannot intercept the reveal tuple and replay it under their own signature.

---

## 3. Phase II: Dynamic Difficulty via Class Groups

The Verifiable Delay Function serves as the primary Sybil-resistance mechanism. A VDF cannot be accelerated through parallel processing — an attacker with 10,000 ASICs cannot compute a single VDF faster than a consumer laptop.

### 3.1 The Mathematical Construction

To maintain a strict trustless philosophy, the protocol constructs its VDF over Class Groups of Imaginary Quadratic Fields [2]. Unlike RSA-based VDFs, Class Groups require no Trusted Setup ceremony.

The client is challenged to compute an output element $y$ within the Class Group given a base element $x$ and a time parameter $T$:
$$ y = x^{2^T} $$

Because the group order is unknown, the client must execute $T$ sequential, non-parallelizable squarings. The prover generates a concise cryptographic proof $\pi$ using the Wesolowski Proof Protocol [2]. Validation by the network takes $O(\log T)$ time, ensuring instant verification for all peers.

### 3.2 The Hardware Baseline & `network.json`

The difficulty baseline is not hardcoded in the binary. It is defined in `network.json` under the key `benchmark_base_iterations` and compiled into all network binaries at build time via `build.rs`. This means:

- **Fork operators** can freely calibrate the baseline to match their network's target hardware.
- **The canonical `.kin` network** uses a baseline of `238,819,830` iterations, calibrated to approximately 30 minutes on a standard Intel Core i5-11400H (≈7.96 million iterations/min).
- **Changing the baseline** requires a network-wide governance update and recompile — it is not a runtime parameter.

> ⚠️ **Warning for fork operators:** Reducing `benchmark_base_iterations` significantly below the `.kin` mainnet value will degrade Sybil resistance. If your fork needs to connect to the global `.kin` network, do not lower this value below the canonical baseline.

### 3.3 The Squatter Cliff: Name-Length Difficulty Scaling

To make mass dictionary squatting physically impossible, the number of required VDF iterations scales non-linearly with name length. Short, premium names require exponentially larger VDFs:

| Label Length | Multiplier | Approximate Time |
|---|---|---|
| 1 character | × 1,753,200 | ~100 years |
| 2 characters | × 1,440 | ~30 days |
| 3 characters | × 1,152 | ~24 days |
| 4 characters | × 720 | ~15 days |
| 5 characters | × 48 | ~1 day |
| 6 characters | × 24 | ~12 hours |
| 7 characters | × 5 | ~2.5 hours |
| 8–10 characters | × 4 | ~2 hours |
| 11–17 characters | × 3 | ~1.5 hours |
| 18–20 characters | × 2 | ~1 hour |
| 21–62 characters | × 1 | ~30 minutes (baseline) |
| 63 characters | Random lottery | 63 seconds to 63 millennia |

The 63-character case is a special cryptographic lottery (the "Jackpot"). The difficulty for a 63-character name is derived by hashing the label against the current `drand` round, producing a pseudo-random difficulty tier. See Section 4 of `kinetic-security.md` for details on the Jackpot tie-breaker.

*(Source: kinetic-core/src/consensus_math.rs:83)*

---

## 4. Phase III: The Hybrid Lease System

To prevent early adopters from permanently hoarding the namespace without instituting monetary renewal fees, Kinetic employs a computational lease system.

### 4.1 Grace-Period Escalation

Ownership is maintained by a localized, continuous cryptographic signature heartbeat broadcast to the DHT. If a client goes offline, the name enters **Grace-Period Escalation**.

An attacker attempting to steal an idle name must compute a challenge VDF whose difficulty is governed by a **quadratic inverse decay** based on idle time:

$$ D_{\text{steal}}(\Delta r) = D_{\text{base}} \times \max\left(1,\ \frac{R_{\text{target}}^2}{(\Delta r + 1)^2}\right) $$

where:
- $D_{\text{base}}$ is the standard registration difficulty for the name
- $R_{\text{target}}$ is `steal_target_rounds` from `network.json` (default: `7,884,000` rounds ≈ 9 months at 3s/round on Quicknet)
- $\Delta r$ is the number of rounds the name has been idle

**Interpretation:** When a name first goes offline ($\Delta r \ll R_{\text{target}}$), the steal difficulty is multiplied by up to $(R_{\text{target}}^2)$ — making theft nearly impossible. As idle time approaches $R_{\text{target}}$, the multiplier decays to 1. Beyond that, the name becomes freely claimable at baseline difficulty, effectively recycling abandoned namespace back to the commons.

### 4.2 The Challenge Window

Even if an attacker successfully computes a valid Challenge VDF, this only opens the **Challenge Window** — it does not immediately transfer ownership. The original owner can return at any moment during this window and reclaim the name instantly with a single standard heartbeat signature. The attacker's CPU expenditure is wasted.

### 4.3 Re-Squaring for Long-Term Claims

For names held for extended periods, the protocol requires periodic **Re-Squaring** VDF computation to counteract single-thread hardware performance improvements over time. This is governed by `RESQUARING_EPOCH_ROUNDS` (currently `5,256,000` rounds ≈ 6 months), defined in `kinetic-core/src/types/vdf.rs`.

---

## 5. Network Constants Summary

All consensus-critical constants are defined in `network.json` and are fork-configurable:

| Constant | Default (`.kin` mainnet) | Description |
|---|---|---|
| `benchmark_base_iterations` | 238,819,830 | VDF iterations at 1× difficulty (≈30 min on i5-11400H) |
| `steal_target_rounds` | 7,884,000 | Rounds until steal difficulty decays to baseline (≈9 months) |
| `drand_period` | 3 | Seconds per `drand` Quicknet pulse |
| `kinetic_genesis_drand_round` | TBD at launch | Absolute `drand` round at network launch |

---

## 6. Conclusion

By linking the unpredictable `drand` Quicknet beacon to sequential, class-group verifiable delay functions, and enforcing a quadratic steal-difficulty decay on idle names, the Kinetic Consensus layer achieves a zero-cost, Sybil-resistant registration pipeline. The entire consensus parameter set is fork-configurable via `network.json`, enabling independent operators to deploy sovereign namespaces calibrated to their specific hardware environment and security requirements.

---

## References

[1] League of Entropy. (2020). *drand: A Distributed Randomness Beacon Daemon.* Retrieved from https://github.com/drand/drand

[2] Wesolowski, B. (2019). *Efficient verifiable delay functions.* In: Ishai, Y., Rijmen, V. (eds.) EUROCRYPT 2019. LNCS, vol. 11478, pp. 379–407. Springer, Cham.

[3] Cohen, H., & Lenstra, H. W. (1984). *Heuristics on class groups of number fields.* Number Theory, Lecture Notes in Mathematics, vol. 1068. Springer, Berlin, Heidelberg.
