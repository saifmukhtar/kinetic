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

At its core, Kinetic is a pure peer-to-peer (P2P) network. There are no central servers, no master nodes, and no privileged relays. We use **libp2p** to handle low-level transport, multiplexing, NAT traversal, and peer discovery. 

The state of the network (which includes DNS records, KID identities, and capabilities manifests) is stored entirely in a Distributed Hash Table (DHT) using the **Kademlia** protocol. Kademlia allows nodes to find the closest peers storing a particular piece of data by calculating the XOR distance between a peer's ID and the data's hash.

However, standard Kademlia is notoriously vulnerable to malicious actors in an open, permissionless setting.

## The Threat: Sybil and Eclipse Attacks

In a vanilla Kademlia DHT, any node can generate a new cryptographic `PeerId` instantly, simply by generating a random Ed25519 keypair. 

If a well-funded attacker wants to censor the domain `alice.kin`, they can exploit this lack of cost. The attacker generates millions of `PeerId`s until they find thousands that are mathematically "close" (in XOR distance) to the hash of `alice.kin`. 

They then flood the network with these nodes. When legitimate nodes attempt to resolve `alice.kin`, the standard Kademlia routing algorithm will inevitably direct their queries to the attacker's nodes, because the attacker has completely surrounded the target hash space. When queried, the attacker's nodes simply return "Record Not Found", drop the connection, or return garbage data.

This devastating attack is known as an **Eclipse Attack**, and it is fundamentally enabled by a **Sybil Attack** (the ability to cheaply generate infinite identities). If identities are free, censorship is cheap.

## S/Kademlia and the Argon2id PoW

To secure the network and guarantee data availability, Kinetic implements the rigorous principles of **S/Kademlia (Secure Kademlia)**. We must make it computationally expensive and time-consuming to generate a valid `PeerId` that the network will accept into its routing tables.

Kinetic enforces a heavy **Proof of Work (PoW)** check on all incoming connections and all DHT routing table insertions. 

We specifically use the **Argon2id** hashing algorithm (Source: `kinetic-network/src/pow.rs`) with the following strict parameters:
- **Memory Cost:** 16 MiB
- **Iterations:** 1
- **Parallelism:** 1

### Why Argon2id and 16 MiB?

Standard hash functions like SHA-256 (used in Bitcoin) are easily accelerated by specialized ASICs (Application-Specific Integrated Circuits) or GPUs. If we used SHA-256 for PeerId generation, an attacker with a mining farm could still generate millions of Sybil identities cheaply and quickly, while regular users on laptops would struggle to generate even one.

Argon2id, on the other hand, is **memory-hard**. It forces the processor to constantly read and write to a 16 MiB block of RAM in an unpredictable, pseudo-random pattern. The primary bottleneck becomes memory bandwidth, not raw processing speed. 

This architectural choice levels the playing field: a GPU or ASIC has extremely limited fast memory cache (SRAM) per core. They cannot parallelize Argon2id hashes efficiently without constantly hitting memory bandwidth limits or running out of onboard cache. 

By enforcing a 16 MiB memory-hard PoW, we ensure that an attacker must expend significant, un-optimizable energy and dedicate massive amounts of RAM simply to join the network. Generating enough Sybil identities to Eclipse a specific hash becomes economically unviable.

## Reactor Starvation and `spawn_blocking`

While the Argon2id PoW elegantly solves the Sybil problem, it introduces a severe software engineering challenge: **Reactor Starvation**.

Because the 16 MiB Argon2id verification is CPU-intensive (taking tens of milliseconds to verify on a standard CPU), it poses a secondary threat to the node's stability.

Kinetic's `kinetic-network` crate runs on a highly concurrent asynchronous event loop using the `tokio` runtime. In an async runtime, a small pool of worker threads handles thousands of connections concurrently by rapidly switching between tasks when waiting for I/O (network traffic). However, if a single task performs heavy CPU math without yielding, it blocks the worker thread. If all worker threads are blocked verifying PoW, the entire node freezes. Active connections drop, DNS queries timeout, and the node becomes unresponsive.

A smart attacker could intentionally open hundreds of connections with completely invalid PoW proofs. If the event loop attempts to verify these on the main async threads, the node locks up—a classic Denial of Service (DoS) attack.

To completely neutralize this threat, Kinetic treats the DHT verification boundary as a critical security perimeter. **All VDF verifications and Argon2id PoW checks are strictly offloaded via `tokio::task::spawn_blocking`**. 

This API moves the heavy cryptographic math off the async runtime and onto a bounded, dedicated background thread pool. Even if an attacker floods the node with fake PoW proofs, the background threads will queue up, but the main async event loop remains completely free to handle legitimate DNS resolution traffic, ping responses, and existing connections. Malicious inbound traffic can never starve the node's primary reactor.
