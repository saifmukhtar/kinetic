# Chapter 6: Exhaustive Code Walkthrough (`kinetic-core` & `kinetic-vdf`)

The theoretical models outlined in the previous chapters are strictly enforced by the Rust code within the Kinetic workspace. In this chapter, we begin an exhaustive, module-by-module breakdown of the system, starting with the two foundational crates: `kinetic-core` and `kinetic-vdf`.

---

## 1. The Mathematical Definitions: `kinetic-core`

The `kinetic-core` crate acts as the shared dictionary for the entire workspace. It contains the exact structural definitions that must be serialized, signed, and validated by every peer in the network.

### 1.1 The Two-Phase Commit Structs

Located in `kinetic-core/src/types.rs`, the ownership lifecycle is governed by two structs: `CommitRequest` and `Reveal`.

#### Phase 1: The Commitment
```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CommitRequest {
    pub name: String,
    pub salt: [u8; 32],
    pub drand_pulse: u64,
    pub pubkey: Vec<u8>,
}
```
This lightweight struct is broadcast instantly. The `salt` ensures that if two users attempt to register the exact same name at the exact same time, their commitment hashes are completely distinct, preventing one from copying the other's VDF.

#### Phase 2: The Reveal
```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VdfProof {
    pub proof_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Reveal {
    pub protocol_version: u16,
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
* **`protocol_version: u16`**: Protocol V2.
* **`pub name: String`**: The requested domain, strictly normalized to a Fully Qualified Domain Name (FQDN) ending in `.kin.` (e.g., `apple.kin.`).
* **`pub payload: Vec<u8>`**: The actual routing target (a serialized `DnsZone`). Must fit within the 64KB DHT limit.
* **`pub drand_pulse` & `pub drand_randomness`**: The exact round number and corresponding entropy fetched from the external Drand beacon. This forms the absolute timestamp of the commitment.
* **`pub iterations: u64`**: The exact number of VDF iterations (Repeated Squarings) the user claims to have computed. The network nodes will verify if this number matches the length-based minimum requirement.
* **`pub vdf_proof: VdfProof`**: A wrapper around the raw bytes returned by the Chia VDF engine. This concise proof allows honest nodes to instantly verify the computation in \\(O(\log T)\\) time.
* **`pub pubkey: Vec<u8>`**: The 32-byte Ed25519 public key of the registrant. 
* **`pub signature: Vec<u8>`**: The 64-byte Ed25519 signature. Crucially, the signature is calculated over a strictly serialized byte array of *all preceding fields*, ensuring that an attacker cannot alter the IP payload without invalidating the signature.

### 1.2 Heartbeats via Rebroadcast

In Protocol V2, there is no separate `Heartbeat` struct. To prove an active lease and defend a name against grace-period escalation, the `kinetic-daemon` simply rebroadcasts the exact `Reveal` struct periodically.

### 1.3 The Dynamic Difficulty Engine

Inside `kinetic-core/src/types.rs`, the `calculate_required_iterations` function is the mathematical enforcer of the dictionary squatter penalty.

```rust
pub fn calculate_required_iterations(name: &str) -> u64 {
    let base_name = name.trim_end_matches(".kin.");
    let len = base_name.len();

    let base_iterations: u64 = 4_194_304; // Baseline for short names
    
    // Minimum 1024 iterations for long names
    if len >= 10 {
        return 1024;
    }
    
    base_iterations / (1 << (len - 1))
}
```

This simple, deterministic function is identical across every node. If a user registers a 1-character name and submits a `Reveal` with too few iterations, the honest DHT nodes instantly drop the hostile payload.

---

## 2. The FFI Boundary & Concurrency Control: `kinetic-vdf`

The `kinetic-vdf` crate is perhaps the most computationally intense part of the workspace. It serves as a bridge between the memory-safe Rust architecture and the official `chiavdf` C++ engine.

### 2.1 The Trait Abstraction

To allow for potential future implementations (such as a pure-Rust VDF or an ASIC-accelerated VDF wrapper), the core logic is abstracted behind the `VdfEngine` trait in `kinetic-core/src/traits.rs`.

```rust
pub trait VdfEngine {
    fn evaluate(&self, challenge: &Commitment, iterations: u64) -> Result<VdfProof, String>;
    fn verify(&self, challenge: &Commitment, iterations: u64, proof: &VdfProof) -> bool;
}
```

### 2.2 Global Mutex via `fs2`

Because VDF generation is intensely CPU-bound and fundamentally unparallelizable, running two VDF grinds concurrently on the same machine destroys cache locality and causes severe OS scheduler thrashing, doubling the completion time for both.

`kinetic-vdf` solves this using `fs2::FileExt`:
```rust
use fs2::FileExt;
use std::fs::OpenOptions;

// Obtain a cross-process lock before hitting the C++ engine
let lock_file = OpenOptions::new()
    .read(true)
    .write(true)
    .create(true)
    .open("/tmp/kinetic_vdf.lock")
    .unwrap();
    
lock_file.lock_exclusive().unwrap(); // Blocks if another VDF is grinding
```

### 2.3 The Chia C++ Bindings

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
