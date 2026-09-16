# Layer 8: System Daemons & Services (Headless Cloud Node)

## 1. Taxonomy
This crate (`kinetic-node`) belongs to **Layer 8**, the topmost execution layer of the workspace. 
It strictly consumes the lower layers (`kinetic-network`, `kinetic-storage`, `kinetic-core`) and acts as a headless, always-on infrastructure process.

## 2. Abstraction Rules
As a Layer 8 executable:
1. **No Core Protocol Logic:** This crate must *never* perform cryptographic math, write generic network structs, or define DHT routing logic. It merely instantiates the `NetworkClient` and `KineticStorage` and ties them together.
2. **Domain Boundaries:** It only interacts with HTTP load balancers and the Gossipsub mesh. It does not speak to user interfaces or DNS.

## 3. Specialized Role
Unlike `kinetic-daemon` (which runs on user laptops), `kinetic-node` is designed to be highly available. It runs the **Time Oracle Heartbeat** loop, which queries external entropy providers and floods those pulses into the mesh, effectively shielding user laptops from making thousands of redundant outbound HTTP requests.
