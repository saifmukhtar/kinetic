# Layer 8: System Daemons & Services

## 1. The Hook (Taxonomy)
This crate (`kinetic-nrs`) belongs to **Layer 8: System Daemons & Services**. It is the Name Resolution System branch that bridges core `.kin` verification logic with external UDP/TCP DNS protocols.

## 2. The Core Architectural Rule (The Invariant)
**This crate must safely isolate standard internet resolution from sovereign `.kin` resolution.**

It relies on `kinetic-verify` to ensure cryptographic proofs are valid, and `kinetic-local` to pull locally trusted settings. However, it must *never* allow external DNS protocols (like a malicious UDP packet) to crash the core consensus rules. It strictly translates DNS wire-format packets into internal HTTP DHT lookups.

## 3. The Horizontal Boundary
This crate exclusively owns the `hickory-dns` server implementation and Moka caching layer.
It explicitly ignores *how* the DHT routes queries or how the network topology works (that is owned by `kinetic-network`). It only cares about listening on port 53 (or similar), inspecting the `apex_name` (e.g., `alice.kin`), and either returning a cached wire-format DNS response or proxying it upstream.

## 4. Why This Exists (Abstraction Defense)
Isolating the Name Resolution System into its own dedicated Layer 8 crate provides two massive benefits:
1. **SSRF & Poisoning Defense:** `kinetic-nrs` acts as a firewall against Server-Side Request Forgery and DNS rebinding attacks before queries ever reach the core daemon.
2. **Pluggable Protocols:** By decoupling the DNS listener from the Kademlia DHT, Kinetic could theoretically add DoH (DNS-over-HTTPS) or DoT (DNS-over-TLS) support inside this crate without modifying a single line of the DHT or core consensus logic.
