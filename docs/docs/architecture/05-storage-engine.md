---
title: '05 — Storage Engine'
prev:
  text: '04 — Network Routing'
  link: '/architecture/04-network-routing'
next:
  text: '06 — Daemon & DNS'
  link: '/architecture/06-daemon-and-dns'
---

# Architecture & Motivation: Storage and State

Kinetic nodes must persist massive amounts of data: their own identities, governance state, their local configuration, and a cache of the global DHT routing table and records. 

Choosing the right storage engine is critical to ensuring node reliability, fast DNS resolution, and preventing catastrophic failure.

## Why Sled?

For native desktop and server deployments, Kinetic uses **Sled**, an embedded, high-performance, thread-safe key-value store written purely in Rust.

Why not SQLite or RocksDB?
1. **No C/C++ FFI:** RocksDB and SQLite rely on massive C/C++ codebases. By using Sled, we keep the storage layer fully within Rust's memory-safe ecosystem, preventing a whole class of buffer overflow and memory corruption vulnerabilities at the persistence layer.
2. **Concurrency:** Sled is designed for highly concurrent, lock-free operations. Since the Kinetic daemon is simultaneously serving local API requests, handling P2P DHT replication, and serving UDP DNS queries, the database must handle immense read/write contention without blocking.
3. **Embedded Footprint:** Sled requires no external database server to be running. It compiles directly into the `kinetic-daemon` binary, adhering to our "one-click install" philosophy.

## The State Separation Architecture

In decentralized networks, disk corruption (from power loss, hardware failure, or OS crashes) is inevitable. How the software responds to corruption defines its robustness. 

Kinetic enforces a strict architectural boundary between two types of data: **The Cache** and **Authoritative State**.

### 1. The Network Cache
This includes the DHT record store, cached DNS zones of other users, and peer routing tables.
- **Rule:** This data is ephemeral. It can be recreated by simply asking the network.
- **Failure Mode:** Safe to wipe. If Sled detects corruption in the cache namespace, Kinetic will gracefully wipe the cache and resync from the network.

### 2. Authoritative State
This includes the user's ML-DSA-65 identity keys, the seed phrase, the VDF `reveal.json` proofs for their owned names, and the network Governance state.
- **Rule:** This data is irreplaceable. If you lose your keys or your VDF proofs, you lose your names. If governance state is wiped, the node could be tricked into accepting malicious root updates.
- **Failure Mode:** **Fail-Closed**. Kinetic will absolutely refuse to run if Authoritative State is corrupted. It will never silently reset to a blank slate, because a blank slate (like reverting Governance back to Phase 1 Founder mode) could compromise the node's security model. The user is required to manually intervene and restore from backups.

By isolating these namespaces, Kinetic ensures that routine disk corruption in the highly volatile P2P cache does not accidentally destroy the user's irreplaceable cryptographic assets.
