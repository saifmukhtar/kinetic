# Chapter 4: VDF Delegation, Heartbeats & Exemption Points

The central dilemma of any free, permissionless registry is **Dead State**. 

If a registry costs nothing, what prevents early adopters from registering thousands of premium names, shutting down their computers, and leaving those names permanently locked and unusable for the next generation of internet users?

Capital-gated registries solve this through recurring financial renewal fees. If you stop paying rent, the registry evicts you, and the name returns to the open market.

Because the Kinetic Protocol is fundamentally zero-cost, it must employ a different eviction mechanism. It replaces monetary rent with localized, ongoing computational life support: **The Hybrid Lease System**.

---

## 1. The Reveal Heartbeat: Active Territory Defense

In Kinetic, ownership is not a static database entry; it is an active state of defense. To maintain control over a name, the owner's `kinetic-daemon` must periodically prove to the network that it is alive, interested, and capable of participating in consensus.

This is achieved simply by rebroadcasting the `Reveal` struct as a **Heartbeat**.

The `Reveal` contains the original mathematical VDF proof, signed by the owner's Ed25519 identity. Because the mathematical proof is tied to a specific name, the daemon simply pushes this exact same payload to the DHT on a regular interval to refresh the lease.

### The Sled Storage Background Loop
The user does not manually trigger these heartbeats. The `kinetic-daemon` natively utilizes `sled`, an embedded, high-performance database written in Rust.

When a user publishes `apple.kin`, the `Reveal` struct is persisted to the local Sled storage engine. 

Upon startup, the daemon spawns an asynchronous `tokio` background task. This task loops infinitely:
1. Load all registered names from Sled.
2. Issue parallel Kademlia `PUT` commands, scattering the `Reveal` across the $M=32$ redundant locations on the DHT.
3. Sleep for a predetermined duration (e.g., 60 seconds).

This process requires a fraction of a megabyte of RAM and almost zero CPU usage. It runs silently, passively defending the user's namespace territory.

---

## 2. VDF Delegation (Mobile Light Clients)

While refreshing a name is mathematically cheap, *registering* a short name (1-7 characters) requires grinding a multi-million iteration VDF.

This creates a hardware paradox: how can a user on a low-power Android or iOS device securely register a name without melting their phone battery?

Kinetic solves this through **VDF Delegation via Nostr**.

1. **The Request:** The mobile `kinetic-client` generates an Ed25519 identity securely within the smartphone's hardware enclave. It creates a `CommitRequest`, but instead of grinding the VDF locally, it wraps the request in a small Hashcash Proof-of-Work (e.g., 20 bits, taking ~2 seconds on a phone).
2. **NIP-04 Encryption:** The phone encrypts this payload using Nostr NIP-04, targeting the public key of the user's home Desktop computer (running `kinetic-daemon`).
3. **The Relay:** The phone fires the message to a public Nostr relay.
4. **The Grind:** The Desktop node, listening to the relay, decrypts the request. Because the request contains a valid Hashcash PoW, the Desktop accepts the job. The Desktop CPU spins up and executes the multi-million iteration VDF.
5. **The Delivery:** Once the mathematical proof is generated, the Desktop node encrypts the final `Reveal` struct and sends it back over Nostr to the phone.
6. **Publishing:** The phone receives the VDF proof, signs it with its localized private key, and publishes it to the network.

This architecture enables true decentralization: your phone holds the private keys, but your desktop acts as your mathematical workhorse.

---

## 3. Exemption Points: Mitigating Power Outages

What happens when the owner goes offline? Perhaps they closed their laptop, or their Desktop node lost internet access due to a power outage.

If a heartbeat flatlines, the Kademlia DHT eventually drops the old records. Does the name instantly vanish? Can a sniper bot instantly register `apple.kin` the second the laptop goes to sleep?

Absolutely not. Kinetic implements **Exemption Points**.

When a user holds a domain for an extended period, the network automatically accrues mathematical "Exemption Points" to that name. 

### The Mathematics of Exemption

An abandoned name does not immediately become "free". Instead, an attacker wishing to steal the name must compute an *exponentially harder* Verifiable Delay Function (VDF) based on exactly how long the name has been held before going offline.

The number of iterations required to steal a name acts as a Grace-Period Escalation:
1. **Day 1 of Offline Time:** If you held the name for a year, the required VDF to steal it is astronomical. It would take an attacker months of continuous, un-parallelizable ASIC computation.
2. **Day 30 of Offline Time:** The exponential decay curve slowly lowers the difficulty as your Exemption Points burn out.
3. **Day 365 of Offline Time:** If you held the name for only a month before abandoning it, the VDF penalty decays to a negligible amount rapidly, and the name can be registered as if it were brand new.

### Initiating the Challenge
To steal an inactive name, an attacker must:
1. Compute the exact decayed threshold $T_{\text{steal}}$.
2. Grind the massive VDF.
3. Broadcast a new `Reveal`.

### The Challenge Window: Effortless Reclaiming
Let us assume the attacker is honest and grinds a massive 3-week VDF to steal an offline domain. They broadcast their hostile `Reveal`.

Does the attacker instantly get the name? No. This merely opens the **Challenge Window**.

For a specific grace period, the network suspends the name in a contested state. If the original owner turns their laptop back on at *any point* during that window, the `kinetic-daemon` instantly wakes up and broadcasts its standard `Reveal` Heartbeat. 

When the DHT nodes see this fresh, perfectly valid Heartbeat signed by the original owner, they immediately erase the attacker's hostile claim. 

The attacker burned three weeks of intense CPU computation. The original owner invalidated it effortlessly with a background heartbeat.

This profound asymmetry perfectly balances fluid namespace recycling with impenetrable ownership rights.
