# Layer 9: User Interfaces & Clients

## 1. Taxonomy
This crate (`kinetic-cli`) belongs to **Layer 9**, the topmost execution layer of the workspace. 
It operates strictly as a User Interface component.

## 2. Abstraction Rules
As a Layer 9 CLI:
1. **Stateless Operations Only:** The CLI must *never* attempt to instantiate the `kinetic-storage` redb database, nor initialize the `kinetic-network` Swarm. 
2. **HTTP REST Boundary:** All actions must be dispatched over HTTP to the `kinetic-daemon` (port `16001`). The CLI is merely a JSON serializer and standard-out formatter.
3. **No Cryptography:** The CLI should not perform signing operations. It sends the command, and the underlying daemon utilizes the `kinetic-local` keystore to sign the payloads.

## 3. Separation of Concerns
By enforcing this boundary, the heavy components (VDF computation, Kademlia routing, OS-level proxy interception) are kept alive safely in the background daemon, while the CLI remains lightweight and instantaneous.
