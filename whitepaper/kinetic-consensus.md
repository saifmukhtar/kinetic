# Technical Paper I: Core Consensus & Proof of Patience

**Author:** Saif Mukhtar
**Date:** July 2026
**Version:** 1.0.0

## Abstract
This paper defines the core cryptographic and mathematical consensus mechanisms of the Kinetic Protocol. To achieve a globally sovereign namespace without a centralized ledger or monetary fees, the protocol utilizes a strictly sequential, three-phase cryptographic lifecycle. By combining Verifiable Delay Functions (VDFs) computed over Class Groups with a distributed randomness beacon, Kinetic neutralizes front-running, dictionary squatting, and dead-state hoarding via an algorithmic Proof of Patience.

---

## 1. Introduction
In a public, permissionless registry, transmitting a plaintext claim for a string exposes the client to front-running. A sniper bot can observe the request in the network mempool and duplicate it with higher network priority. To counter this, legacy systems rely on financial bidding wars. Kinetic instead introduces a "Proof of Patience," ensuring that registering a name requires a provable expenditure of un-parallelizable time, effectively blinding automated sniping algorithms.

## 2. Phase I: Clockless Front-Running Neutralization

Kinetic neutralizes front-running via Sequential VDF Linking anchored to an external randomness beacon (`drand`) [1].

Let $S$ be the set of valid human-readable strings, and let $n \in S$ be the target name.

1. **Commitment Generation:** The client generates a high-entropy salt $s \in \{0,1\}^{256}$ and fetches the latest `drand` pulse $B_{t_1}$. The client cryptographically binds their public key into the hash commitment:
   $$ C = H(n \parallel s \parallel B_{t_1} \parallel \text{PubKey}) $$
2. **Sequential Linking:** The client uses $C$ as the base seed input for a massive Verifiable Delay Function (VDF) computation requiring $T$ time to evaluate.
3. **The Reveal:** Upon VDF completion, the client broadcasts the plaintext tuple $(n, s, B_{t_1}, \text{VDF}_{\text{proof}})$. 

Because $B_{t_1}$ is unpredictable, the VDF cannot be pre-computed. Because the VDF inherently takes $T$ time, its completion mathematically proves that the commitment $C$ existed at least $T$ time ago. Sniper bots are rendered blind. Furthermore, because $C$ embeds the original $\text{PubKey}$, a sniper cannot intercept the reveal tuple and replay it wrapped in their own signature.

## 3. Phase II: Dynamic Difficulty via Class Groups

The Verifiable Delay Function (VDF) serves as the primary Sybil-resistance mechanism. A VDF cannot be accelerated through parallel processing; an attacker with 10,000 ASICs cannot compute a single VDF faster than a consumer laptop.

### 3.1 The Mathematical Construction
To maintain a strict trustless philosophy, the protocol constructs its VDF over Class Groups of Imaginary Quadratic Fields [2]. Unlike RSA-based VDFs, Class Groups require no "Trusted Setup" ceremony.

The client is challenged to compute an output element $y$ within the Class Group given a base element $x$ and a time parameter $T$:
$$ y = x^{2^T} $$

Because the group order is unknown, the client must execute $T$ sequential, non-parallelizable squarings. The prover generates a concise cryptographic proof $\pi$ using the Wesolowski Proof Protocol [2]. Validation by the network takes $O(\log T)$ time, ensuring instant verification.

### 3.2 Dynamic Difficulty Scaling
To prevent the Sybil defense from decaying as hardware single-thread performance improves, the baseline difficulty constant $k$ is deterministically derived from the `drand` beacon height. This provides global difficulty adjustment with zero coordination overhead.

If the beacon is unreachable, the protocol gracefully degrades to a static difficulty, requiring a periodic "re-squaring" VDF for long-term claims to counteract hardware inflation.

## 4. Phase III: The Hybrid Lease System

To prevent early adopters from permanently hoarding the namespace without instituting monetary renewal fees, Kinetic employs a computational lease system.

### 4.1 Grace-Period Escalation
Ownership is maintained by a localized, continuous cryptographic signature heartbeat. If a client goes offline, the name enters **Grace-Period Escalation**.

An abandoned name requires an attacker to compute an *exponentially harder* VDF to steal it, based on how long it has been idle:
$$ T_{\text{steal}}(\Delta t) = T_{\text{max}} \cdot e^{-\beta \cdot \Delta t} $$

where $\Delta t$ is the idle time, $T_{\text{max}}$ is the initial massive VDF difficulty, and $\beta$ is the decay constant.

To initiate a challenge, the attacker must prove the idle time using the DHT state (referencing the last known `drand` heartbeat). Even if the attacker computes a valid Challenge VDF, it merely opens the **Challenge Window**. The original owner can return at any moment during this window and reclaim the name instantly with a single standard heartbeat.

### 4.2 Hibernation and Delegation
* **Hibernation VDFs:** For planned long-term offline periods, users can burn a 48-hour sequential VDF to obtain a 1-year heartbeat exemption certificate, halting the grace-period clock.
* **Watchtower Delegation:** Users can pre-generate a chain of signed heartbeat tokens and delegate them to decentralized nodes to broadcast on schedule, achieving trust-minimized uptime without continuous local computation.

## 5. Conclusion
By linking unpredictable random beacons to sequential verifiable delay functions, the Kinetic Consensus layer achieves a zero-cost, Sybil-resistant registration pipeline that eliminates the need for monetary auctions and centralized governance.

---

## References

[1] League of Entropy. (2020). *drand: A Distributed Randomness Beacon Daemon.* Retrieved from https://github.com/drand/drand

[2] Wesolowski, B. (2019). *Efficient verifiable delay functions.* In: Ishai, Y., Rijmen, V. (eds.) EUROCRYPT 2019. LNCS, vol. 11478, pp. 379–407. Springer, Cham.
