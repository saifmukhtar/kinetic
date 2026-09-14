# Layer 5: Executables (Heavy User Engine)

## 1. Taxonomy
This crate (`kinetic-daemon`) belongs to **Layer 5**, the topmost execution layer of the workspace. 
It bundles all underlying Layer 4 infrastructure traits (`kinetic-network`, `kinetic-storage`, `kinetic-vdf`, `kinetic-nrs`) into a single, cohesive orchestrator process.

## 2. Abstraction Rules
As a Layer 5 executable:
1. **No Core Protocol Logic:** This crate must *never* perform cryptographic math, rewrite generic network structs, or define underlying DHT logic. It relies on the isolated lower-level crates.
2. **Domain Boundaries:** It represents the absolute edge of the Kinetic workspace. It receives JSON via the REST API from Electron, acts upon it, and pushes state down into the Layer 4 orchestrators. 

## 3. Specialized Role
Unlike `kinetic-node` (infrastructure) or `kinetic-host` (headless seeder), this daemon is extremely "heavy." It is stateful. It caches `.kin` namespace lookups to disk, runs a background VDF CPU miner, runs an OS-level DNS interceptor, and dynamically MITMs HTTPS traffic using a self-signed Root CA. It is meant to be run directly on user hardware.
