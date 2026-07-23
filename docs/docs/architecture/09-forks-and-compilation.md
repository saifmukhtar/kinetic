---
title: '09 — Forks & Compilation'
prev:
  text: '08 — Client Architecture'
  link: '/architecture/08-client-architecture'
next:
  text: '10 — Threat & Trust Model'
  link: '/architecture/10-threat-and-trust-model'
---

# Architecture & Motivation: The Engine, Forks, and Compilation

Kinetic is not just a single network; it is an **Engine**. While there is a primary public network, the protocol is explicitly designed to be instantiated as private campus networks, corporate intranet naming systems, or community-specific TLDs.

However, running multiple discrete networks presents a critical security risk: **Cross-Network Pollution**.

## The Cross-Network Pollution Threat

If a user is running a daemon connected to a private corporate network (`.corp`), and another user is running a daemon on the public network (`.kin`), what prevents the corporate records from accidentally leaking into the public DHT? 

In many P2P systems, the network ID is just a string in a JSON config file that the user loads at runtime. If a user accidentally starts their corporate daemon with the public config file, their corporate DNS zones and capability manifests will immediately be broadcast to the public internet DHT.

## The Compile-Time Solution: `build.rs` and `network.json`

Kinetic completely eliminates cross-network pollution by making the network identity a **compile-time constant**.

When you compile Kinetic, the `build.rs` script reads a `network.json` file. This file contains the cryptographic root keys, the Genesis block parameters, the Top-Level Domain (TLD) constraint, and the network magic bytes. 

The build script hardcodes these values directly into the Rust binary. 

### Why Compile-Time?
1. **Zero Runtime Mistakes:** A `kinetic-corp` binary mathematically cannot connect to the public `kinetic-mainnet` DHT. The network magic bytes and protocol handshake strings are compiled into the binary. They will reject each other's TCP connections immediately.
2. **Cryptographic Hardcoding:** The ML-DSA-65 Root Key public bytes are hardcoded into the binary. This means an attacker cannot trick a node into accepting a malicious Over-The-Air (OTA) update by simply modifying a local JSON config file to point to the attacker's key. The binary only trusts the key it was compiled with.

## `kinetic-forge`

To make this compile-time architecture developer-friendly, we built `kinetic-forge`.

`kinetic-forge` is a CLI tool that automatically generates a new `network.json` file, mints new ML-DSA-65 Root and Guard keys, and scaffolds a completely isolated, independent Kinetic network. It allows an enterprise to spin up their own cryptographically isolated naming layer in minutes, compile the binaries, and distribute them to their employees, knowing with absolute certainty that their network will never bleed into the public internet.
