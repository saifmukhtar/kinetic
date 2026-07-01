# Kinetic Adversarial Analysis
## A Red-Team Audit of Stateless Name Resolution

**Draft Research Whitepaper v0.2**

## Abstract
Robust protocol design requires assuming the worst possible operational environment. Because Kinetic utilizes an Untrusted Gateway model for Light Client resolution, the system’s security relies entirely on the deterministic mathematical rules executed by the client-side resolver. 

This document serves as an adversarial analysis of the Kinetic resolution mathematics. We assume an adversary has full control over the untrusted gateways, can forge Sybil identities at will, and possesses significant (but not majority) computational hash power. We evaluate seven specific attack vectors designed to subvert ownership resolution and detail the deterministic cryptographic rules that neutralize them.

---

## Attack 1: The Split View Attack (Two Valid Leases)

**The Attack:**
An attacker discovers a highly desirable name (`apple.kin`). They compute a perfectly valid VDF, generate a mathematically sound commitment, and sign it. Simultaneously, an honest user does the exact same thing. 
A malicious gateway returns *both* Lease Record X (Attacker) and Lease Record Y (Honest User) to the resolving browser. Both records are structurally sound and mathematically valid.

**The Cryptographic Mitigation (Deterministic Selection):**
The Kinetic protocol strictly mandates a deterministic conflict-resolution rule to prevent state divergence. The client-side resolver evaluates the payloads using the following hierarchy:
1. **Oldest Original Commitment:** The resolver compares the `drand_pulse` contained within the VDF `Reveal`. The payload with the chronologically earliest legitimate pulse instantly wins. This prevents an attacker from "stealing" a name by computing a VDF years later.
2. **The XOR Tie-Breaker (Protocol V2):** If and only if both users committed to the name within the exact same 30-second `drand` window, the resolver executes the XOR Lottery. The winner is the payload whose VDF output bytes possess the smallest XOR distance to the *subsequent* `drand` pulse ($B_{t+1}$). Because neither user can predict $B_{t+1}$ during their commitment phase, the tie-breaker is a mathematically un-gameable, perfectly fair lottery.

---

## Attack 2: The Heartbeat Race (The Offline Owner)

**The Attack:**
Alice owns `saif.kin`. Her local daemon crashes, or her internet service drops, causing her to miss her heartbeat broadcast. An attacker's automated script detects the missed heartbeat and immediately begins computing a VDF to claim the "abandoned" name.

**The Cryptographic Mitigation (Grace-Period Escalation):**
Kinetic does not instantly evict offline names. The difficulty for the attacker to steal the name ($T_{\text{steal}}$) scales inversely proportional to the idle time ($\Delta t$). 

The required VDF iterations are calculated via the Grace-Period Escalation curve:
$$ T_{\text{steal}} = T_{\text{base}} \times e^{\left(\frac{k}{\Delta t}\right)} $$
*(where $k$ is the escalation constant and $\Delta t$ is the elapsed `drand` rounds since the last heartbeat).*

If an attacker attempts to snipe a name that has only been offline for 1 hour, $\Delta t$ is small, driving $T_{\text{steal}}$ into the trillions. This requires computing a VDF that would physically take years to finish. 
By the time the attacker's server finishes computing this massive proof, Alice will likely have reconnected to the internet and published a single, instant heartbeat (a `Reveal` rebroadcast). The resolver will see Alice's newer heartbeat, resetting $\Delta t$ to zero, and instantly invalidating the attacker's years of wasted computation.

---

## Attack 3: The DHT Eclipse (Mitigating Kademlia Sybil Attacks)

**The Attack:**
The Light Client queries three untrusted Gateways to resolve a name. The Gateways are honest, but the Kademlia DHT underlying the network is being attacked. An adversary controls hundreds of Sybil nodes and successfully suppresses the newest lease records, feeding the Gateways outdated, poisoned DHT state.

**The Cryptographic Mitigation (Keyspace Independence):**
A local resolver cannot mathematically detect *missing* records, only *invalid* ones. To combat this network-layer censorship, Kinetic utilizes $M=32$ distinct storage keys derived via a cryptographic hash function:
- $K_1 = \text{SHA256}(\text{name} \parallel 1)$
- $K_2 = \text{SHA256}(\text{name} \parallel 2)$
- $\dots$
- $K_{32} = \text{SHA256}(\text{name} \parallel 32)$

Because the Kademlia DHT routes based on a 256-bit XOR metric, the SHA-256 avalanche effect guarantees that these 32 keys are statistically uncorrelated and land in completely disparate regions of the global Kademlia ring. Eclipsing the neighborhood around $K_1$ provides zero advantage toward eclipsing $K_{32}$. 

To successfully censor the newest record, the attacker must simultaneously eclipse all $M$ regions. The probability of successfully eclipsing all $M$ keys drops exponentially: $P_{\text{eclipse}} \approx f^{k \cdot M}$ (where $f$ is the attacker's fraction of global hash power and $k$ is the bucket size). 

With $M=32$ and an attacker controlling 20% of the network ($f=0.2$):
$$ P_{\text{total eclipse}} = (0.2)^{32} \approx 4.29 \times 10^{-23} $$

Unless the attacker commands a supermajority of the global network's identity-generation power, successfully censoring the DHT is statistically impossible.

---

## Attack 4: The Historical Rewrite (Preventing Replay Attacks)

**The Attack:**
An attacker archives a perfectly valid, VDF-proven `Reveal` Record from the year 2028. In the year 2035, the attacker replays this exact record to the network, attempting to trick a resolver into thinking the 2028 owner is still the current owner.

**The Cryptographic Mitigation (Drand Entanglement):**
In Protocol V2, the `drand_pulse` acts as both the commitment anchor and the heartbeat age. The daemon continuously signs the latest `drand_pulse` as it rebroadcasts the `Reveal`.
When the 2028 record is replayed in 2035, the resolver calculates the idle time ($\Delta t$) by subtracting the heartbeat's 2028 `drand_pulse` from the current 2035 `drand` pulse. The resolver determines the name has been "dead" for 7 years. 
Under the Grace-Period Escalation curve, the VDF difficulty to claim a name dead for 7 years is trivially small. Any honest user currently holding the name in 2035 will have a newer `Reveal`, causing the resolver to effortlessly discard the replayed 2028 record as obsolete.

---

## Attack 5: Name Popularity Attack (DDoS Mitigation via Verification Asymmetry)

**The Attack:**
A name like `openai.kin` becomes globally famous. An attacker floods the DHT with tens of thousands of valid, but mathematically losing, VDF leases. 
Because the DHT nodes must evaluate incoming leases to drop the weaker ones (Competitive Gossip Filtering), the attacker's goal shifts from crashing the Browser to exhausting the CPU of the DHT nodes. This is a Resolution DDoS attack targeting infrastructure validators.

**The Cryptographic Mitigation (Verification Asymmetry):**
This attack is neutralized by the fundamental asymmetry of the chosen VDF construction (Class Groups of Imaginary Quadratic Fields). 
While *generating* a valid proof is strictly sequential and extremely slow ($O(T)$), **verifying the proof is exponentially faster ($O(\log T)$)**.

A DHT node can cryptographically verify a fake lease in mere milliseconds. An attacker attempting to spam 1 million fake leases must physically compute 1 million sequential VDF proofs—an operation requiring vast server farms and massive energy expenditure. The DHT nodes will trivially filter and drop these 1 million leases using negligible CPU power. The attacker bankrupts themselves long before the infrastructure notices the load.

---

## Attack 6: KID Continuity (The Identity Shift)

**The Attack:**
A highly trusted name, `bank.kin`, expires after years of inactivity and is legally claimed by a malicious actor. The malicious actor generates a new Permanent Identity Document (KID) and publishes a new Capability Manifest pointing to a phishing API. Users resolving `bank.kin` are silently routed to the phishing server because the math resolves perfectly.

**The Cryptographic Mitigation (KID Pinning):**
This is a semantic vulnerability inherent to all dynamic naming systems (e.g., DNS hijacking). Kinetic solves this by strictly separating Names from Identities.
High-security applications must treat human-readable names merely as *initial discovery vectors*. Once an application successfully resolves `bank.kin` to `kid1abc...`, the application should locally "pin" the KID. Future connections must assert that the resolved KID matches the pinned KID. If the Name changes hands, the resolved KID will change, immediately triggering a security warning (similar to an SSH host key changing). Trust is strictly bound to the immutable cryptography (KID), not the mutable alias (Name).

---

## Attack 7: Long Range Resurrection (The Semantic Attack)

**The Attack:**
Similar to Attack 6, `openai.kin` is abandoned. Ten years later, an attacker legitimately claims it. Now, `openai.kin` points to a completely different KID. Millions of old forum links, archived manifests, and historical documents still reference `openai.kin`. Clicking those links now routes users to the attacker's services.

**The Cryptographic Mitigation (The Core Identity Principle):**
This attack highlights a core design principle of Kinetic: **Names are ephemeral routing aliases; KIDs are permanent semantic anchors.**
To prevent Long Range Resurrection, the ecosystem standard dictates that historical references, permanent storage (like IPFS), and immutable smart contracts must *never* hardcode `.kin` names. They must hardcode the underlying KID. 
When a user shares a permanent document, the software should automatically embed the underlying KID rather than the human-readable alias, completely immunizing historical data from future name re-registration attacks.
