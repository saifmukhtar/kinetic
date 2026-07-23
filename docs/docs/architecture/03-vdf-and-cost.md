# Architecture & Motivation: Replacing Money with Time (VDFs)

In traditional naming systems, preventing "squatting" (registering every dictionary word to hoard them) relies on **financial friction**. You pay ICANN/registrars an annual fee, or you pay gas/tokens on a blockchain. 

Kinetic eliminates financial fees to ensure the network remains free and accessible globally. To prevent squatting without money, Kinetic substitutes financial friction with **computational time**. 

## The Flaw of Proof of Work (PoW) for Naming

If we just need a computational cost, why not use standard Proof of Work (like Bitcoin's SHA-256 or Ethereum's old Ethash)? 

Because PoW is **highly parallelizable**. If registering a 4-letter name required a PoW hash that takes 15 days on a standard laptop, a wealthy attacker could rent an AWS cluster with 10,000 cores and compute the proof in exactly two minutes. The defense collapses against capital. Money simply buys parallel compute, which buys all the short names.

## The Solution: Verifiable Delay Functions (VDFs)

To make time an uncheatable metric, we use a **Verifiable Delay Function (VDF)**. 

A VDF is a cryptographic function that requires a prescribed number of *sequential* steps to compute. It cannot be parallelized. Even if an attacker has 10,000 CPU cores, they cannot compute the VDF any faster than a single core running at the maximum possible clock speed. 

If Kinetic dictates that a 4-letter name requires `N` sequential squarings in a class group, the computation will take approximately 15 days of wall-clock time, period. Capital cannot bypass this limit.

Furthermore, while the VDF takes days to *compute* (the proof), it takes only milliseconds for any node on the network to *verify* the output.

### Why the Chia C++ VDF?

Implementing a mathematically sound VDF, specifically one based on repeated squaring in unknown order groups (Class Groups of Imaginary Quadratic Fields), is an incredibly difficult cryptographic engineering task. 

Rather than writing a pure-Rust implementation from scratch and risking subtle mathematical vulnerabilities, Kinetic uses the battle-tested **Chia VDF**. 
We bind the Chia C++ implementation directly into Rust via FFI (`kinetic-vdf/src/lib.rs`). This guarantees we are relying on production-grade, audited cryptographic code that currently secures billions of dollars of value on the Chia network.

## The Randomness Beacon: Drand

For a VDF to act as a secure proof of time for a *specific* name registration, the challenge seed must be unpredictable and provably generated *after* the user's intent to register. If the challenge was predictable, an attacker could pre-compute VDFs years in advance.

Kinetic uses **Drand (League of Entropy's Quicknet)** as a public randomness beacon.

1.  A user publishes a hash commitment to their name.
2.  They fetch the latest unpredictable random pulse from Drand.
3.  They use this randomness as the seed for their VDF computation.

### The `SHA-256(sig)` Binding Invariant

Relying on external endpoints for randomness introduces a severe Man-in-the-Middle (MITM) threat. If an attacker controls the DNS routing for the Drand HTTP endpoint, they could return a fake payload.

To prevent this, Drand pulses are signed using BLS signatures by the League of Entropy's pinned public key. However, verifying the signature is **not sufficient**.

An attacker could forward a *valid* signature from a real round but append their own maliciously crafted `randomness` value to the JSON payload. If the Kinetic daemon only checked the signature, it would accept the attacker's randomness, allowing the attacker to steer the VDF challenge.

To mitigate this, Kinetic enforces a strict cryptographic binding (Source: `kinetic-core/src/drand.rs:121`):
`randomness == SHA-256(signature)`

The resolver mathematically derives the randomness directly from the validated BLS signature. This ensures that no MITM or rogue endpoint can inject chosen randomness, ensuring the VDF challenge is always authentically derived from the globally trusted beacon.
