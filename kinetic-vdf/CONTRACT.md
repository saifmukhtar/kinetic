# Crate Contract: `kinetic-vdf`

## 1. Domain Purpose
This is the **Proof of Patience (Physics)** layer. Its singular role is to implement a deterministic, non-parallelizable Wesolowski Verifiable Delay Function (VDF) over a hardcoded RSA-2048 group. It acts as the physical clock mechanism restricting the speed of identity registrations.

## 2. Pre-conditions (What the caller MUST do)
* **Thread Management:** The `evaluate()` function is intentionally CPU-bound and blocks indefinitely. The caller (Daemon) MUST wrap this call in a dedicated OS thread pool (e.g., `tokio::task::spawn_blocking`) to prevent starving the async runtime.
* **Provide Difficulty:** The caller MUST supply the exact `iterations` required. This engine does not know how to calculate network difficulty targets.
* **Commitment Construction:** The caller MUST correctly assemble the 32-byte SHA-256 `Commitment` (the starting point `x`) based on the previous block state. 

## 3. Post-conditions & Guarantees (The "Always")
* **Mathematical Determinism:** Guarantees absolute determinism in the Prover (`evaluate`). Given the same Commitment and iterations, it will always produce the exact same 512-byte proof buffer `(y, pi)`, preventing consensus splits.
* **Fast Verification:** Guarantees that `verify()` is exponentially faster to compute than `evaluate()`, allowing nodes to instantly validate months of computational work.
* **Degenerate Protection:** Guarantees that mathematically degenerate inputs (like an all-zero challenge $x=0$) are instantly rejected with `VdfError::InvalidChallenge`, preventing trivial proof bypasses.

## 4. Anti-Guarantees (The "Never")
* **Zero Consensus Difficulty:** This crate NEVER checks if the provided `iterations` count matches the current network requirement. It blindly executes the math it is told to do.
* **Zero Temporal Context:** This crate NEVER knows what a `Kyn` (network time) is. It only understands CPU iterations.
* **Zero Network Transport:** This crate NEVER listens to the swarm or broadcasts proofs.

## 5. Trust Boundaries & Dependencies
* **Internal:** Fully trusts `kinetic-primitives` (for SHA-256) and `kinetic-types` (for struct layouts).
* **External:** Fully trusts the `rug` crate and the system's underlying GMP library for arbitrary-precision arithmetic and prime generation.
