# Chapter 4: Heartbeats and Dead-State Neutralization

The central dilemma of any free, permissionless registry is **Dead State**. 

If a registry costs nothing, what prevents early adopters from registering thousands of premium names, shutting down their computers, and leaving those names permanently locked and unusable for the next generation of internet users?

Capital-gated registries (like ENS or traditional ICANN DNS) solve this through recurring financial renewal fees. If you stop paying rent, the registry evicts you, and the name returns to the open market.

Because the Kinetic Protocol is fundamentally zero-cost, it must employ a different eviction mechanism. It replaces monetary rent with localized, ongoing computational life support: **The Hybrid Lease System**.

---

## 1. The PoW Heartbeat: Active Territory Defense

In Kinetic, ownership is not a static database entry; it is an active state of defense. To maintain control over a name, the owner's `kinetic-daemon` must periodically prove to the network that it is alive, interested, and capable of participating in consensus.

This is achieved via a **Proof of Work (PoW) Heartbeat**.

A Heartbeat is an incredibly lightweight cryptographic struct, generated and broadcast by the owner's daemon every 60 seconds.

$$ \text{Heartbeat} = \text{Sign}_{\text{Ed25519}} ( \text{Name} \parallel \text{drand\_pulse}_{t} ) $$

The daemon automatically queries the external Drand beacon for the latest entropy pulse, binds it to the domain name, and signs it with the exact same Ed25519 private key that was used during the initial VDF Reveal. 

### The Sled Storage Background Loop
The user does not manually trigger these heartbeats. The `kinetic-daemon` natively utilizes `sled`, an embedded, high-performance database written in Rust.

When a user registers `apple.kin`, the `Reveal` struct and the corresponding Ed25519 keypair are immediately persisted to the local Sled storage engine. 

Upon startup, the daemon spawns an asynchronous `tokio` background task. This task loops infinitely:
1. Load all registered names from Sled.
2. Fetch the latest Drand pulse.
3. Construct and sign a Heartbeat for every name.
4. Issue a Kademlia `PUT` command, scattering the Heartbeats across the DHT (utilizing the Redundant Deterministic Storage mechanisms discussed in Chapter 3).
5. Sleep for 60 seconds.

This process requires a fraction of a megabyte of RAM and almost zero CPU usage. It runs silently, passively defending the user's namespace territory.

---

## 2. Grace-Period Escalation: The Mechanics of a Hostile Takeover

What happens when the owner goes offline? Perhaps they closed their laptop, lost internet access, or intentionally abandoned the name.

If a heartbeat flatlines, the Kademlia DHT eventually drops the old records. Does the name instantly vanish? Can a sniper bot instantly register `apple.kin` the second the laptop goes to sleep?

Absolutely not. Kinetic implements **Grace-Period Escalation**.

An abandoned name does not immediately become "free". Instead, an attacker wishing to steal the name must compute an *exponentially harder* Verifiable Delay Function (VDF) based on exactly how long the name has been idle. 

### The Mathematics of Stealing

Let $\Delta t$ be the idle time (the time elapsed since the last valid Heartbeat was seen on the DHT).
Let $T_{\text{max}}$ be the maximum possible VDF penalty (e.g., millions of iterations, requiring weeks of computation).
Let $\beta$ be the exponential decay constant.

The number of iterations required to steal a name is formalized as:

$$ T_{\text{steal}}(\Delta t) = T_{\text{max}} \cdot e^{-\beta \cdot \Delta t} $$

* **Day 1 of Offline Time:** The required VDF is astronomical. It would take an attacker three months of continuous, un-parallelizable ASIC computation to steal the name.
* **Day 30 of Offline Time:** The exponential decay curve lowers the difficulty. It might now take the attacker three weeks of computation.
* **Day 365 of Offline Time:** The name is functionally dead. The VDF penalty decays to a negligible amount, and the name can be registered as if it were brand new.

### Initiating the Challenge
To steal a name without a centralized clock, the attacker must mathematically prove to the Kademlia swarm exactly how long the name has been dead.

1. The attacker queries the DHT and retrieves the last known valid Heartbeat for `apple.kin`. (This heartbeat contains a specific Drand pulse number, definitively marking its exact creation time).
2. The attacker calculates the elapsed Drand rounds $\Delta t$.
3. The attacker's local `kinetic-cli` calculates the required penalty iterations $T_{\text{steal}}(\Delta t)$.
4. The attacker grinds the massive VDF.
5. The attacker broadcasts a new `Reveal` struct, embedding the original owner's last Heartbeat to prove the $\Delta t$ variable.

### The Kademlia Record Store Enforcement
When the DHT nodes receive this hostile `Reveal`, the `KineticRecordStore` executes the following logic:
1. Verify the attacker's VDF.
2. Inspect the embedded "Last Known Heartbeat" the attacker provided.
3. Check the node's own local cache: Does the node have a *newer* Heartbeat for `apple.kin`?

If the honest node possesses a Heartbeat newer than the one the attacker claims is the "last", the attacker's entire computation is instantly invalidated. The attacker is flagged for attempting a fraudulent takeover, and their connection is dropped.

This means an attacker cannot simply ignore recent heartbeats to artificially shorten $\Delta t$. They must be mathematically honest about the exact time of death.

---

## 3. The Challenge Window: Effortless Reclaiming

Let us assume the attacker is honest. The laptop has been closed for 30 days. The attacker spends three grueling weeks grinding a massive VDF penalty to steal `apple.kin`.

The attacker finally finishes the VDF and broadcasts the hostile `Reveal`. 

Does the attacker instantly get the name? No. This merely opens the **Challenge Window**.

For the next 7 days, the network suspends the name in a contested state. The Kademlia DHT stores both the original owner's identity and the attacker's pending claim. 

If the original owner turns their laptop back on at *any point* during those 7 days, the `kinetic-daemon` instantly wakes up, fetches the latest Drand pulse, and broadcasts a standard 60-second Heartbeat. 

When the DHT nodes see this fresh, perfectly valid Heartbeat signed by the original owner, they immediately erase the attacker's hostile claim. 

The attacker burned three weeks of intense, maximum-load CPU computation. The original owner invalidated it effortlessly with a 50-millisecond background heartbeat.

This profound asymmetry is the core of Kinetic's deterrence. Stealing a name is mathematically grueling, economically irrational, and completely uncertain, while maintaining a name is effortless and guaranteed. 

Through Heartbeats and Grace-Period Escalation, Kinetic perfectly balances fluid namespace recycling with impenetrable ownership rights.
