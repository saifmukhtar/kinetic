---
title: '03 — VDF & Cost'
prev:
  text: '02 — Cryptography & Identity'
  link: '/architecture/02-cryptography-and-identity'
next:
  text: '04 — Network Routing'
  link: '/architecture/04-network-routing'
---

# Architecture & Motivation: Replacing Money with Time (VDFs)

In traditional naming systems (like DNS or blockchain-based alternatives like ENS), preventing "squatting"—the practice of registering every dictionary word to hoard and resell them—relies entirely on **financial friction**. You pay ICANN and centralized registrars an annual fee in fiat currency, or you pay gas and token renewal fees on a blockchain smart contract. 

Kinetic completely eliminates financial fees to ensure the network remains fundamentally free and accessible globally as a public utility. However, to prevent bad actors from squatting the entire namespace at zero cost, Kinetic substitutes financial friction with an unforgeable physical constraint: **computational time**. 

## The Flaw of Proof of Work (PoW) for Naming

If we just need to impose a computational cost on registration, why not use standard Proof of Work (like Bitcoin's SHA-256 or older CPU-bound algorithms)? 

The critical flaw in standard Proof of Work is that it is **highly parallelizable**. If we designed the protocol so that registering a 4-letter name required a PoW hash that takes 15 days to compute on a standard laptop, a wealthy attacker could simply rent an AWS cluster with 10,000 cores. By parallelizing the hashing search space across all cores, they could compute the 15-day proof in roughly two minutes.

Against PoW, the defense collapses entirely against capital. Money simply buys parallel compute, which buys all the short, valuable names instantly. This recreates the financial gatekeeping we explicitly set out to avoid.

## The Solution: Verifiable Delay Functions (VDFs)

To make time a truly egalitarian and uncheatable metric, Kinetic uses a **Verifiable Delay Function (VDF)**. 

A VDF is a cryptographic function that requires a prescribed number of *strictly sequential* steps to compute. The output of step `N` is fundamentally required as the input for step `N+1`. Therefore, the computation cannot be parallelized. 

Even if an attacker possesses 10,000 CPU cores or a specialized supercomputer, they cannot compute the VDF any faster than a single core running at the maximum possible clock speed. Because single-thread CPU performance has largely plateaued globally (within a small margin of difference between a consumer laptop and an enterprise server), the playing field is leveled.

If Kinetic dictates that a 4-letter name requires `N` sequential squarings in a mathematical group, the computation will take approximately 15 days of wall-clock time for *anyone*, period. Capital cannot bypass this limit.

Furthermore, a VDF possesses a magical property: while it takes days to *compute* the proof (the delay), it takes only a few milliseconds for any node on the network to *verify* that the output is correct.

### Why the Chia C++ VDF?

Implementing a mathematically sound VDF—specifically one based on repeated squaring in unknown order groups (Class Groups of Imaginary Quadratic Fields)—is an incredibly difficult and error-prone cryptographic engineering task. 

Rather than writing a pure-Rust implementation from scratch and risking subtle mathematical vulnerabilities, Kinetic uses the battle-tested **Chia VDF**. 
We bind the official Chia C++ implementation directly into Rust via Foreign Function Interface (FFI) in the `kinetic-vdf` crate. This guarantees we are relying on highly optimized, production-grade, audited cryptographic code that currently secures billions of dollars of value on the Chia blockchain network.

## The Randomness Beacon: Drand

For a VDF to act as a secure proof of time for a *specific* name registration, the mathematical challenge seed must be entirely unpredictable and provably generated *after* the user decided to register the name. If the challenge seed was predictable, an attacker could pre-compute VDF proofs for thousands of names years in advance and submit them all at once.

To guarantee seed unpredictability, Kinetic uses **Drand (League of Entropy's Quicknet)** as a decentralized, public randomness beacon.

The registration lifecycle is as follows:
1.  A user publishes a cryptographic hash commitment to their desired name on the network.
2.  They fetch the latest unpredictable random pulse from the Drand Quicknet.
3.  They use this randomness as the seed (the starting point) for their VDF computation.

### The `SHA-256(sig)` Binding Invariant

Relying on external endpoints (like Drand HTTP relays) for randomness introduces a severe Man-in-the-Middle (MITM) threat. If an attacker controls the DNS routing or the local network connection for the Drand endpoint, they could intercept the request and return a fake payload with chosen randomness, allowing them to pre-compute the VDF.

To prevent this, Drand pulses are signed using BLS signatures by the League of Entropy's pinned threshold public key. However, verifying this signature is **not sufficient** on its own.

An attacker could forward a *valid* signature from a real, historical Drand round but append their own maliciously crafted `randomness` value to the JSON payload. If the Kinetic daemon only checked the validity of the signature, it would mistakenly accept the attacker's chosen randomness, completely bypassing the VDF time lock.

To strictly mitigate this, Kinetic enforces a hard cryptographic binding at the core protocol layer (Source: `kinetic-core/src/drand.rs`):
`randomness == SHA-256(signature)`

The resolver ignores the `randomness` field provided in the JSON payload entirely. Instead, it mathematically derives the randomness directly by hashing the validated BLS signature itself. This ensures that no MITM attacker, rogue endpoint, or malicious peer can inject chosen randomness. The VDF challenge is always authentically and securely derived from the globally trusted League of Entropy beacon, preserving the integrity of the time-lock mechanism.
