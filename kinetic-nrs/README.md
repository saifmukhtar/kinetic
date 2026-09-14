# kinetic-nrs

## 1. Overview
`kinetic-nrs` (Name Resolution System) is the high-performance DNS resolver for the Kinetic Network. It intercepts DNS queries for `.kin` domains and routes them to the Kinetic DHT, while seamlessly forwarding all normal internet traffic (e.g., `.com`, `.org`) to the host operating system's native DNS resolvers.

## 2. Usage & Integration
This crate provides the `KineticNrsHandler`, which implements the `RequestHandler` trait from the `hickory-server` crate. It is primarily orchestrated by the `kinetic-daemon` to spin up a local DNS server (e.g., on `127.0.255.1:53`).

```rust
// Example integration pattern
use hickory_server::ServerFuture;
use kinetic_nrs::KineticNrsHandler;

let handler = KineticNrsHandler::new("http://127.0.0.1:8080".into(), atlas_nsps, 16001);
let mut server = ServerFuture::new(handler);
server.register_listener(udp_socket, tcp_listener);
```

## 3. Internal Architecture & The Threat Model
Because `kinetic-nrs` acts as a local DNS interceptor, it must be highly performant and secure against DNS-based attack vectors:
*   **Asymmetric Moka Caching (`src/cache.rs`):** It uses high-speed, thread-safe `moka` caches to store DNS wire-format responses. Positive `.kin` resolutions are cached for 5 minutes, while negative (NXDOMAIN) responses are cached for 30 seconds to prevent DDoS via non-existent domain spamming.
*   **SSRF & Reserved Name Filtering (`src/kinetic_records.rs`):** To prevent malicious `.kin` records from resolving to internal IPs (like `169.254.169.254` AWS metadata servers), the resolution pipeline aggressively filters out private network ranges. Furthermore, it strictly intercepts RFC reserved public utility names (`localhost.kin`, etc.) and resolves them deterministically, bypassing the DHT entirely.
*   **Background OS Hot-Reloading (`src/lib.rs`):** The handler spawns a background Tokio task that hot-reloads the OS's native DNS settings (e.g., `/etc/resolv.conf`) every 5 minutes. If a user switches from Wi-Fi to a Cellular network, `kinetic-nrs` automatically discovers the new upstream ISP resolvers without restarting.

## 4. Reading Guide
To fully understand this crate, we recommend reading it in the following order:

### Prerequisites
* **kinetic-core:** You must understand `RESERVED_NAMES` and the `NrsZone` data structures.
* **kinetic-verify:** You should understand how sovereign signatures are validated, as `kinetic-nrs` relies on those proofs when unwrapping the DHT payloads.

### File Traversal (Leaf-First)
Read this crate in the following order:
1. `src/cache.rs` - Understand the `moka` caching layer and its asymmetric TTL logic.
2. `src/upstream.rs` - See how standard `.com` queries are forwarded to the OS or Cloudflare fallback.
3. `src/kinetic_records.rs` - The heart of the crate. Read this to understand how `.kin` domains are resolved via HTTP, verified, and converted into standard `hickory_proto::rr::Record` A/AAAA/TXT formats.
4. `src/handler.rs` - The central router that splits queries between `kinetic_records` and `upstream`.
5. `src/lib.rs` - The module map and background task orchestration.

## 5. Taxonomy & Links
* **Taxonomy:** This crate belongs to Layer 4. Please read [`./LAYER_4.md`](./LAYER_4.md) to understand the strict architectural constraints of this layer.
* **Repository:** [https://github.com/saifmukhtar/kinetic](https://github.com/saifmukhtar/kinetic)
