---
title: '04 — Network Routing'
prev:
  text: '03 — VDF & Cost'
  link: '/architecture/03-vdf-and-cost'
next:
  text: '05 — Storage Engine'
  link: '/architecture/05-storage-engine'
---

# Architecture & Motivation: Network and Sybil Resistance

At its core, Kinetic is a peer-to-peer (P2P) network. We use **libp2p** to handle low-level transport, multiplexing, NAT traversal, and peer discovery. The state of the network (DNS records, KID identities, manifests) is stored entirely in a distributed hash table (DHT) using the **Kademlia** protocol.

However, standard Kademlia is highly vulnerable to malicious actors.

## The Threat: Sybil and Eclipse Attacks

In a vanilla Kademlia DHT, any node can generate as many `PeerId`s as they want instantly. 

If an attacker wants to censor `alice.kin`, they can generate thousands of `PeerId`s that are mathematically "close" to the hash of `alice.kin`. They then flood the network. When legitimate nodes attempt to resolve `alice.kin`, the Kademlia routing algorithm will inevitably direct their queries to the attacker's nodes, because the attacker has surrounded the target hash. The attacker simply returns "Record Not Found" or drops the connection. 

This is known as an **Eclipse Attack**, enabled by a **Sybil Attack** (cheap identity generation).

## S/Kademlia and the Argon2id PoW

To secure the network, Kinetic implements the principles of **S/Kademlia (Secure Kademlia)**. We must make it computationally expensive to generate a valid `PeerId` that the network will accept.

Kinetic enforces a heavy **Proof of Work (PoW)** check on all incoming connections and DHT routing table insertions. 

We specifically use **Argon2id** (Source: `kinetic-network/src/pow.rs:62`) with the following strict parameters:
- **Memory Cost:** 16 MiB
- **Iterations:** 1
- **Parallelism:** 1

### Why Argon2id and 16 MiB?

Standard hash functions (like SHA-256) are easily accelerated by ASICs or GPUs. If we used SHA-256 for PeerId generation, an attacker with specialized hardware could still generate millions of Sybil identities cheaply.

Argon2id is **memory-hard**. It forces the processor to constantly read and write to 16 MiB of RAM in an unpredictable pattern. Memory bandwidth is the primary bottleneck. This levels the playing field: a GPU or ASIC has limited fast memory cache, meaning it cannot parallelize Argon2id hashes efficiently without running out of memory bandwidth. 

By enforcing a 16 MiB memory-hard PoW, we ensure that an attacker must expend significant, un-optimizable energy simply to join the network, making large-scale Sybil and Eclipse attacks economically unviable.

## Reactor Starvation and `spawn_blocking`

Because the 16 MiB Argon2id verification is CPU-intensive (taking tens of milliseconds to verify), it poses a secondary threat: **Reactor Starvation**.

Kinetic's `kinetic-network` crate runs on a highly concurrent asynchronous event loop (Tokio). In an async runtime, if a single task blocks the thread to do heavy CPU math, all other concurrent connections (DNS queries, DHT lookups, API requests) freeze. 

An attacker could open hundreds of connections with invalid PoW proofs. If the event loop verifies these on the main async thread, the entire node locks up (a Denial of Service).

To prevent this, Kinetic treats the DHT verification boundary as a critical security perimeter. **All VDF verifications and Argon2id PoW checks are strictly offloaded via `tokio::task::spawn_blocking`**. This moves the heavy cryptographic math to a bounded, dedicated background thread pool, guaranteeing that malicious inbound traffic can never starve the node's primary event loop or degrade DNS resolution speeds.
