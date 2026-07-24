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

Kinetic nodes must persist massive amounts of data: their own identities, governance state, their local configuration, and a massive cache of the global DHT routing table and network records. 

Because Kinetic aims to be a silent, ubiquitous daemon running on everything from enterprise cloud servers to consumer laptops and Raspberry Pis, choosing the right storage engine is critical. It must ensure node reliability, enable lightning-fast DNS resolution, and rigorously prevent catastrophic failure without requiring a dedicated database administrator.

## Why Sled?

For native desktop and server deployments, Kinetic uses **Sled**, an embedded, high-performance, thread-safe key-value store written purely in Rust.

When architecting the storage layer, the industry standards are typically RocksDB (C++) or SQLite (C). Kinetic intentionally avoids them for three core reasons:

1. **Zero C/C++ FFI (Foreign Function Interface):** RocksDB and SQLite rely on massive, legacy C/C++ codebases. By binding to them, a Rust application inherits their entire attack surface. By using Sled, we keep the storage layer completely within Rust's strict memory-safe ecosystem. This structurally prevents a whole class of buffer overflows, use-after-free bugs, and memory corruption vulnerabilities at the persistence layer.
2. **Lock-Free Concurrency:** Sled is built around a lock-free Bw-Tree architecture, designed specifically for modern, highly concurrent systems. Since the `kinetic-daemon` is simultaneously serving local REST API requests, handling hundreds of P2P DHT replication streams, and resolving UDP DNS queries in real-time, the database must handle immense read/write contention. Sled achieves this without the heavy lock contention that plagues traditional embedded databases.
3. **Embedded Footprint and Zero-Config:** Sled requires no external database server process (like PostgreSQL or Redis) to be running or configured. It compiles directly into the `kinetic-daemon` binary. This strictly adheres to our "one-click install" philosophy. A user simply runs the binary, and the database initializes itself seamlessly in the application data directory.

## The State Separation Architecture

In decentralized peer-to-peer networks, disk corruption—whether from sudden power loss, hardware failure, or operating system crashes—is an inevitable reality. How the node software responds to corruption defines its robustness. 

Many blockchain clients attempt to automatically "heal" or reset themselves upon corruption, which can lead to disastrous edge cases where a node silently forks itself off the network. Kinetic takes a more rigorous approach by enforcing a strict architectural boundary between two types of data: **The Network Cache** and **Authoritative State**.

### 1. The Network Cache
This namespace includes the DHT record store, cached DNS zone files of other users, and `libp2p` peer routing tables.
- **Rule:** This data is entirely ephemeral. It represents a snapshot of the network that can be recreated simply by asking the network again.
- **Failure Mode:** **Fail-Open / Auto-Wipe**. If Sled detects page corruption in the cache namespace during startup, Kinetic will gracefully wipe the cache directory and boot up. It will then dynamically resync the missing state from its peers. This ensures the node stays online for DNS resolution despite minor local disk faults.

### 2. Authoritative State
This namespace includes the user's ML-DSA-65 identity private keys, their secure seed phrase, the VDF `reveal.json` proofs for their owned names, and the network's globally synced Governance state.
- **Rule:** This data is strictly irreplaceable and security-critical. If you lose your keys or your VDF proofs, you permanently lose access to your `.kin` names. If the governance state is wiped, the node could be tricked into accepting malicious root updates or rolling back to an outdated consensus rulebook.
- **Failure Mode:** **Strictly Fail-Closed**. Kinetic will absolutely refuse to boot if it detects even a single byte of corruption in the Authoritative State. It will intentionally panic and exit with a fatal error. It will *never* silently reset to a blank slate, because a blank slate (such as reverting the Governance engine back to its Phase 1 Founder mode) could completely compromise the node's security model. In this scenario, the user or system administrator is explicitly required to intervene and restore the state from secure backups. 

By cryptographically isolating these namespaces, Kinetic ensures that routine disk corruption in the highly volatile P2P cache does not accidentally wipe the user's irreplaceable cryptographic assets or compromise the node's governance integrity.
