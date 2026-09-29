# Crate Contract: `kinetic-action`

## 1. Domain Purpose
This is the **State Transition & Governance** layer (Layer 4). Its singular role is to evaluate and execute highly privileged `SignedNetworkAction` commands (e.g., Sovereign Key rotations, network parameter upgrades, emergency halts) against an in-memory state machine.

## 2. Pre-conditions (What the caller MUST do)
* **Provide Persistence:** The caller MUST load the current `ActionState` from their local database (Sled/SQLite) and provide it as a mutable reference. 
* **Provide Temporal Context:** The caller MUST supply the `current_kyn` from the Time Oracle so this crate can reject stale or replayed actions.
* **Apply Side Effects:** When `execute_action` returns an `ActionEffect` (e.g., a Sovereign Key rotation), the caller is strictly responsible for saving that new state to disk and informing the rest of the application.

## 3. Post-conditions & Guarantees (The "Always")
* **State Machine Isolation:** Guarantees that a `SignedNetworkAction` cannot mutate the `ActionState` unless it perfectly satisfies the cryptographic signature requirements, replay-window checks, and semantic rules of the active engine.
* **Pluggable Consensus:** Guarantees that validation rules are strictly bound to the active network model (e.g., a `Permissionless` network will safely reject Sovereign actions that a `Sovereign` network would accept).

## 4. Anti-Guarantees (The "Never")
* **Zero Persistence:** This crate NEVER writes to the local filesystem or database. It operates purely on the provided in-memory `&mut ActionState`.
* **Zero Transport:** This crate NEVER listens to the P2P swarm for incoming actions. The Daemon must route parsed actions into the engine.

## 5. Trust Boundaries & Dependencies
* **Internal:** Fully trusts `kinetic-types` for the action definitions, `kinetic-kyn` for time types, and `kinetic-primitives` for the underlying cryptographic verification math.
* **External:** Fully operates in an offline, pure mathematical sandbox.
