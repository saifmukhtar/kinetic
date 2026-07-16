# Chapter 9: Exhaustive Code Walkthrough (`kinetic-client` & FFI)

The previous chapters detailed the desktop and server infrastructure of Kinetic. However, mobile devices represent the vast majority of modern internet usage. Running a full Kademlia DHT node and computing massive VDF proofs on a smartphone would instantly drain the battery and violate OS background execution policies.

To solve this, Kinetic provides `kinetic-client`, a cross-platform mobile application built in Flutter (Dart) that interfaces with the Rust core via Foreign Function Interface (FFI). It resides in a separate repository (`/home/saif/kinetic-client`), rather than as a standard workspace crate.

In this chapter, we dissect how the mobile client acts as a lightweight, secure gateway to the Kinetic network without melting your phone.

---

## 1. The Architectural Boundary: `flutter_rust_bridge`

The mobile application is split into two strict domains:
1. **The UI Thread (Dart):** Handles animations, user interactions, OS permissions, and native Flutter screens for the Kinetic dashboard.
2. **The Core Engine (Rust):** Handles cryptographic signing, DHT resolution, and payload validation via the `kinetic-ffi` crate.

These two worlds communicate using `flutter_rust_bridge` (FRB). FRB automatically generates safe C-bindings and Dart wrappers for Rust functions.

### The Rust FFI API (`kinetic-ffi`)

The Rust side exposes high-level asynchronous functions. Unlike the Desktop daemon, the mobile client runs as a light client. The entry points are separated into specialized modules within `kinetic-ffi/src/api/`:

*   **`daemon.rs` (`init_light_client()`)**: Initializes the lightweight Kademlia node that queries the DHT but does not store data for other peers.
*   **`resolver.rs`**: Handles intercepts for the mobile WebView, ensuring `kin://` URLs are securely resolved and routed.
*   **`delegation.rs`**: Manages the complex Nostr/HTTP flow required to outsource VDF computation to desktop nodes.

### The Dart UI Invocation

The mobile app has native Flutter screens for the UI and only uses the WebView for resolving and viewing external `kin://` domains.

---

## 2. Dynamic Axum Proxies & WebView Interception

A major challenge for mobile is securely rendering `kin://` domains within a standard Flutter WebView.

Instead of running a single fixed server on port `16001`, the mobile client uses **dynamic Axum proxies**. When the user navigates to a `kin://` domain, the FFI layer intercepts the request. 

It calls `get_or_spawn_transport_bridge()` to spin up a temporary, dynamically allocated Axum server bound to a random localhost port specifically for that domain. 
*   **LRU Eviction**: To prevent memory leaks and port exhaustion, the bridge manager uses LRU eviction, maintaining a maximum of 10 active bridges at a time.
*   The Flutter WebView is then seamlessly redirected to this temporary localhost port, allowing the user to browse the decentralized site exactly as if it were a standard HTTPS website.

---

## 3. VDF Delegation via Nostr & HTTP

The most computationally expensive operation in Kinetic is domain registration. Because a smartphone cannot physically compute a 4-million iteration VDF without overheating, it delegates the math to a Desktop node.

### The Delegation Flow

1.  **Mobile Request (`delegation.rs`)**: The Rust engine generates a new Ed25519 identity, fetches the Drand pulse, creates the `CommitRequest`, and generates a small Hashcash Proof-of-Work to deter spam.
2.  **Encrypted Transport**: The request is encrypted and published either via a Nostr Relay (`wss://relay.kinetic.network`) or a direct HTTP fallback.
3.  **Desktop Grind**: The Desktop node verifies the PoW, computes the massive VDF proof, and returns the encrypted `Reveal` bytes to the phone.
4.  **Finalization**: The mobile phone signs the final payload with its locally secured private key and broadcasts it to the DHT. 

The private key never leaves the phone, ensuring maximum security while outsourcing the unfeasible math.

---

## 4. Background Heartbeats & Hardware Attestation

Kinetic names require periodic "heartbeats" (rebroadcasting the Reveal) to remain active. 

*   **Background Heartbeat Task**: The mobile app utilizes the Flutter `workmanager` plugin to wake up periodically in the background. It retrieves the encrypted Ed25519 keys securely stored via `FlutterSecureStorage`, signs the heartbeat, and broadcasts it to the DHT without requiring the user to open the app.
*   **Hardware Attestation**: To combat massive botnets registering names from emulators, the mobile client integrates Hardware Attestation (Google Play Integrity API for Android and DeviceCheck for iOS). This ensures that delegation requests are originating from real, uncompromised physical devices.
