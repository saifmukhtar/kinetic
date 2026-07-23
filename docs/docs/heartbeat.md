---
title: Name Lifecycle & Heartbeats
prev:
  text: 'P2P Routing & The Immunological DHT'
  link: '/network_architecture'
next:
  text: 'The Zero-Dollar Split-DNS Gateway'
  link: '/dns_loopback'
---

# Chapter 4: Name Lifecycle & Heartbeats

The central dilemma of any free, permissionless registry is **Dead State**. 

If a registry costs nothing, what prevents early adopters from registering thousands of premium names, shutting down their computers, and leaving those names permanently locked and unusable for the next generation of internet users?

Capital-gated registries solve this through recurring financial renewal fees. If you stop paying rent, the registry evicts you, and the name returns to the open market.

Because the Kinetic Protocol is fundamentally zero-cost, it must employ a different eviction mechanism. It replaces monetary rent with localized, ongoing computational life support.

---

## 1. The Reveal Heartbeat: Active Territory Defense

In Kinetic, ownership is not a static database entry; it is an active state of defense. To maintain control over a name, the owner's `kinetic-daemon` must periodically prove to the network that it is alive, interested, and capable of participating in consensus.

This is achieved simply by rebroadcasting the `Reveal` struct as a **Heartbeat**.

The `Reveal` contains the original mathematical VDF proof, signed by the owner's Ed25519 identity. Because the mathematical proof is tied to a specific name, the daemon simply pushes this exact same payload to the DHT on a regular interval to refresh the lease.

### The Sled Storage Background Loop
The user does not manually trigger these heartbeats. The `kinetic-daemon` natively utilizes `sled`, an embedded, high-performance database written in Rust.

When a user publishes `example.kin`, the `Reveal` struct is persisted to the local Sled storage engine. 

Upon startup, the daemon spawns an asynchronous `tokio` background task. This task loops infinitely:
1. Load all registered names from Sled.
2. Issue parallel Kademlia `PUT` commands, scattering the `Reveal` across the $M=32$ redundant locations on the DHT.
3. Sleep for a predetermined duration.

This process requires a fraction of a megabyte of RAM and almost zero CPU usage. It runs silently, passively defending the user's namespace territory.

---

## 2. Inactivity and The Steal Difficulty Decay

What happens when the owner goes offline? Perhaps they closed their laptop, or their Desktop node lost internet access due to a power outage.

If a heartbeat flatlines, the Kademlia DHT eventually drops the old records. Does the name instantly vanish? Can a sniper bot instantly register `example.kin` the second the laptop goes to sleep?

Absolutely not. Kinetic implements an **Inactivity Decay**.

An abandoned name does not immediately become "free". Instead, an attacker wishing to steal the name must compute an *exponentially harder* Verifiable Delay Function (VDF) based on how long it has been idle relative to the global steal target rounds.

### The Mathematics of Decay

The number of iterations required to steal a name acts as a Grace-Period Escalation:
1. **Early Offline Time:** If you held the name and just went offline, the required VDF to steal it is multiplied astronomically (based on the ratio of target rounds to idle rounds squared). It would take an attacker massive, continuous computation to override your original claim.
2. **Extended Offline Time:** The multiplier decays quadratically as the name remains idle.
3. **Fully Abandoned:** Once the idle time exceeds the network's steal target rounds, the VDF penalty decays to a negligible multiplier (1x), and the name can be registered as if it were brand new.

### Effortless Reclaiming

To steal an inactive name, an attacker must compute the massive, dynamically scaled VDF. But let us assume the attacker decides to grind a massive multi-week VDF to steal a recently offline domain, and they broadcast their hostile `Reveal`.

If the original owner turns their laptop back on at *any point*, the `kinetic-daemon` instantly wakes up and broadcasts its standard `Reveal` Heartbeat. 

When the DHT nodes see this fresh, perfectly valid Heartbeat signed by the original owner (which requires no new VDF computation), they immediately erase the attacker's hostile claim. The attacker burned weeks of intense CPU computation. The original owner invalidated it effortlessly with a standard background heartbeat.

This profound asymmetry perfectly balances fluid namespace recycling with impenetrable ownership rights.
