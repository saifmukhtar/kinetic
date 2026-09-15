# Layer 8: System Daemons & Services (Payload Seeder)

## 1. Taxonomy
This crate (`kinetic-host`) belongs to **Layer 8**, the topmost execution layer of the workspace. 
It strictly consumes the lower layers (`kinetic-network`, `kinetic-storage`, `kinetic-core`) and acts as an autonomous background daemon.

## 2. Abstraction Rules
As a Layer 8 executable:
1. **No Core Protocol Logic:** This crate must *never* perform cryptographic math, write generic network structs, or define DHT routing logic. It merely instantiates the `NetworkClient` and `KineticStorage` and ties them together.
2. **Domain Boundaries:** It only interacts with incoming P2P Proxy Requests and routes them to local backend HTTP servers. It does not speak to user interfaces, does not interact with the local DNS daemon, and does not parse user CLI commands.

## 3. Specialized Role
Unlike `kinetic-node` (which stays online using a static identity), `kinetic-host` acts as a public namespace seeder. Because it must fight Sybil attacks like any normal user, it is subjected to the strict Proof-of-Work threshold constraints. This crate is uniquely designed to run the **Seamless Hot-Swap**, dynamically rotating its entire P2P network identity at the start of every time epoch without dropping active proxy connections.
