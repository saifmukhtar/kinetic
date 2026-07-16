# kinetic-test: Simulation Testing

Building a decentralized, peer-to-peer network requires rigorous testing across hundreds of simultaneous nodes. Standard unit tests are insufficient for validating Kademlia DHT convergence, Sybil resistance, and network partitioning. 

This is the purpose of the `kinetic-test` crate.

## Purpose and Architecture

`kinetic-test` is a dedicated simulation testing environment. It allows developers to programmatically spin up dozens or hundreds of virtual `kinetic-daemon` instances within a single machine or CI environment, all communicating over localized loopback interfaces or simulated network conditions.

### Key Capabilities

*   **DHT Convergence Testing**: Tests whether a domain registered on Node A successfully propagates and resolves on Node Z, passing through an arbitrary number of intermediate simulated peers.
*   **Adversarial Simulation**: Allows for the injection of "malicious" nodes that broadcast invalid VDF proofs or attempt to spam the network, validating that honest nodes successfully drop the malicious payloads and ban the offending IP addresses.
*   **Performance Benchmarking**: Measures the latency and memory overhead of the VDF validation pipeline under extreme load, ensuring the system remains stable when flooded with concurrent Kademlia requests.

By segregating these complex, long-running integration tests into `kinetic-test`, the core workspace remains clean, and CI pipelines can explicitly isolate the heavy P2P simulations from standard unit logic.
