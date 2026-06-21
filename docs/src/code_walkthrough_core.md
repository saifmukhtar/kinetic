# Chapter 6: Exhaustive Code Walkthrough (`kinetic-core` & `kinetic-vdf`)

The theoretical models outlined in the previous chapters are strictly enforced by the Rust code within the Kinetic workspace. In this chapter, we begin an exhaustive, module-by-module breakdown of the system, starting with the two foundational crates: `kinetic-core` and `kinetic-vdf`.

---

## 1. The Mathematical Definitions: `kinetic-core`

The `kinetic-core` crate acts as the shared dictionary for the entire workspace. It contains the exact structural definitions that must be serialized, signed, and validated by every peer in the network.

### 1.1 The `Reveal` Struct

Located in `kinetic-core/src/types.rs`, the `Reveal` struct is the payload generated after a successful VDF computation. It is the core object passed to the DHT.

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VdfProof {
    pub proof_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Reveal {
    pub name: String,
    pub payload: Vec<u8>,
    pub salt: [u8; 32],
    pub drand_pulse: u64,
    pub drand_randomness: String,
    pub iterations: u64,
    pub vdf_proof: VdfProof,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}
```

#### Line-by-Line Breakdown:
* **`#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]`**: We use the `serde` framework extensively. Because these structs traverse the network via Kademlia, they must be seamlessly serialized to and from binary (typically via JSON or Bincode depending on the exact network transport layer).
* **`pub name: String`**: The requested domain, strictly normalized to a Fully Qualified Domain Name (FQDN) ending in `.kin.` (e.g., `apple.kin.`).
* **`pub payload: Vec<u8>`**: The actual routing target. For Phase 1 of Kinetic, this is a UTF-8 encoded string representing an IP address (e.g., `192.168.1.100`). In the future, this can hold an IPFS CID or an Onion address.
* **`pub salt: [u8; 32]`**: A 32-byte high-entropy array. This ensures that if two users attempt to register the exact same name at the exact same time, their commitment hashes are completely distinct, preventing one from copying the other's VDF.
* **`pub drand_pulse` & `pub drand_randomness`**: The exact round number and corresponding entropy fetched from the external Drand beacon. This forms the absolute timestamp of the commitment.
* **`pub iterations: u64`**: The exact number of VDF iterations (Repeated Squarings) the user claims to have computed. The network nodes will verify if this number matches the length-based minimum requirement.
* **`pub vdf_proof: VdfProof`**: A wrapper around the raw bytes returned by the Chia VDF engine. This concise proof allows honest nodes to instantly verify the computation in \\(O(\log T)\\) time.
* **`pub pubkey: Vec<u8>`**: The 32-byte Ed25519 public key of the registrant. 
* **`pub signature: Vec<u8>`**: The 64-byte Ed25519 signature. Crucially, the signature is calculated over a strictly serialized byte array of *all preceding fields*, ensuring that an attacker cannot alter the IP payload without invalidating the signature.

### 1.2 The `Heartbeat` Struct

Also located in `kinetic-core/src/types.rs`, the `Heartbeat` is the lightweight payload used to continuously defend a domain against the Grace-Period Escalation Protocol.

```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Heartbeat {
    pub name: String,
    pub drand_pulse: u64,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}
```

* **`drand_pulse: u64`**: The heartbeat's proof of current time. When the `kinetic-daemon` background loop wakes up every 60 seconds, it fetches the current pulse. Because Drand pulses are unpredictable, an attacker cannot pre-generate future heartbeats.
* **`signature: Vec<u8>`**: The signature proves that the person submitting the heartbeat genuinely possesses the original `pubkey` used in the initial `Reveal`. 

### 1.3 The Dynamic Difficulty Engine

Inside `kinetic-core/src/types.rs`, the `calculate_required_iterations` function is the mathematical enforcer of the dictionary squatter penalty.

```rust
pub fn calculate_required_iterations(name: &str) -> u64 {
    // Strip the trailing ".kin." for accurate length calculation
    let base_name = name.trim_end_matches(".kin.");
    let len = base_name.len();

    let base_iterations: u64 = 10_000_000;
    
    // Exponential scale down: base_iterations / (2 ^ length)
    // Ensures very short names (1-2 chars) are prohibitively difficult
    // while longer names (5+ chars) are easy.
    if len <= 1 {
        base_iterations / 2
    } else if len >= 20 {
        // Floor for very long names
        base_iterations / (1 << 20) 
    } else {
        base_iterations / (1 << len)
    }
}
```

This simple, deterministic function is identical across every node. If a user registers a 1-character name (`a.kin.`) and submits a `Reveal` with \\(T = 100,000\\) iterations, the honest DHT nodes will run this function, see that 5,000,000 iterations were required, and instantly drop the hostile payload.

---

## 2. The FFI Boundary: `kinetic-vdf`

The `kinetic-vdf` crate is perhaps the most computationally intense part of the workspace. It serves as a bridge between the memory-safe Rust architecture and the official `chiavdf` C++ engine.

### 2.1 The Trait Abstraction

To allow for potential future implementations (such as a pure-Rust VDF or an ASIC-accelerated VDF wrapper), the core logic is abstracted behind the `VdfEngine` trait in `kinetic-core/src/traits.rs`.

```rust
pub trait VdfEngine {
    fn evaluate(&self, challenge: &Commitment, iterations: u64) -> Result<VdfProof, String>;
    fn verify(&self, challenge: &Commitment, iterations: u64, proof: &VdfProof) -> bool;
}
```

### 2.2 The Chia C++ Bindings

Inside `kinetic-vdf/src/lib.rs`, the `ChiaVdfEngine` implements this trait using Rust's Foreign Function Interface (FFI). 

```rust
pub struct ChiaVdfEngine;

impl VdfEngine for ChiaVdfEngine {
    fn evaluate(&self, challenge: &Commitment, iterations: u64) -> Result<VdfProof, String> {
        let discriminant_size_bits = 1024;
        let mut proof_bytes = Vec::new();
        
        // This makes an FFI call down to the linked C++ chiavdf library
        // prove_vdf() utilizes imaginary quadratic class groups of unknown order
        let success = chiavdf::prove_vdf(
            &challenge.hash,
            discriminant_size_bits,
            iterations,
            &mut proof_bytes,
        );

        if success {
            Ok(VdfProof { proof_bytes })
        } else {
            Err("Chia VDF proof generation failed".to_string())
        }
    }

    fn verify(&self, challenge: &Commitment, iterations: u64, proof: &VdfProof) -> bool {
        let discriminant_size_bits = 1024;
        
        // The verify call executes in O(log T) or O(1) time
        chiavdf::verify_vdf(
            &challenge.hash,
            discriminant_size_bits,
            iterations,
            &proof.proof_bytes,
        )
    }
}
```

#### Line-by-Line Breakdown:
* **`let discriminant_size_bits = 1024;`**: The discriminant specifies the mathematical size of the Imaginary Quadratic Class Group. A 1024-bit discriminant offers a robust security margin against classical factorization attacks (equivalent to approximately RSA-3072).
* **`chiavdf::prove_vdf`**: This is a blocking call. When `kinetic-cli` invokes this, the thread is completely hijacked by the C++ engine. The CPU will max out a single core, aggressively executing the \\(x^{2^T}\\) repeated squarings. Because this operation cannot be parallelized, giving it multiple threads does not speed it up.
* **`chiavdf::verify_vdf`**: This is where the magic of the VDF lies. When a DHT node receives the proof, it calls this function. Even if `iterations` is 50,000,000 (representing weeks of work), `verify_vdf` returns `true` or `false` in a fraction of a millisecond.

This stark asymmetry between `prove_vdf` and `verify_vdf` is what makes the Immunological DHT possible. Nodes can relentlessly verify millions of proofs with virtually zero CPU overhead, while attackers must burn astronomical amounts of physical time to generate even a single valid proof.

Through `kinetic-core` and `kinetic-vdf`, the protocol defines an unbendable, mathematically strict rulebook that governs every interaction within the network.
