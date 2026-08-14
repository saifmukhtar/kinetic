# Kinetic — Architecture
 
This document explains how Kinetic is put together, so a new contributor (or an
auditor) can navigate the codebase and understand where trust boundaries lie.
 
Kinetic is an **engine**: the public `.kin` network is the reference deployment,
but every network-defining value (NSP, DID prefix, governance model, drand beacon,
bootstrap nodes, cost parameters) is read from `network.json` at build time and
baked into constants by `build.rs`. Forks change `network.json` and recompile.
 
---
 
## 1. High-level picture
 
```
                        ┌───────────────────────────────────────────┐
   user / app           │                kinetic-daemon              │
  ┌───────────┐  HTTP   │  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
  │  client   │────────▶│  │ local API│  │ split-DNS│  │  proxy   │  │
  │ (Tauri /  │  :API   │  │ (Axum)   │  │  :53     │  │  :17001  │  │
  │  ext/CLI) │         │  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
  └───────────┘         │       │             │             │        │
                        │       ▼             ▼             ▼        │
                        │  ┌───────────────────────────────────┐    │
                        │  │       kinetic-network (libp2p)      │    │
                        │  │  Kademlia DHT · Gossipsub · mDNS ·  │    │
                        │  │  AutoNAT · relay · DCUtR · UPnP     │    │
                        │  └───────┬───────────────┬────────────┘    │
                        │          │               │                 │
                        │   ┌──────▼─────┐   ┌──────▼──────┐          │
                        │   │kinetic-vdf │   │kinetic-     │          │
                        │   │(Chia FFI)  │   │storage (KV) │          │
                        │   └────────────┘   └─────────────┘          │
                        └───────────────────────────────────────────┘
                                   │                      │
                             ┌─────▼─────┐          ┌─────▼─────┐
                             │  drand    │          │ bootstrap │
                             │ (beacon)  │          │  / seeds  │
                             └───────────┘          └───────────┘
```

---

## 2. Crates

| Crate | Responsibility | Trust-sensitive parts |
|-------|----------------|-----------------------|
| `kinetic-core` | Shared types, config, name rules, drand client, governance state machine + engines | Randomness binding, Sovereign root logic, `is_valid_apex_name`, canonical signing bytes |
| `kinetic-types` | Core DNS, wire types, host routing records, and domain structures | Serialization, record constraints, bounds |
| `kinetic-verify` | Pure Rust & WASM VDF verification, discriminant derivation, BQFC serialization | Deserialization, group arithmetic, proof checks |
| `kinetic-vdf` | Rust bindings to Chia's C++ VDF engine | `unsafe` FFI, discriminant handling, proof verification |
| `kinetic-vdfrs` | Rust-native VDF engine wrapper | Mathematical equivalence, verification |
| `kinetic-tlock` | Time-lock Identity-Based Encryption (IBE) over Drand rounds (Roadmap) | Round binding, ciphertext integrity |
| `kinetic-network` | libp2p swarm, Kademlia DHT, record store + validation, PoW, event loop | Inbound `PutRecord` validation, PoW checks, `spawn_blocking` placement, bounded maps |
| `kinetic-storage` | Persistence abstraction over `sled` (native) / in-memory (wasm) | Corruption recovery, cache-vs-authoritative separation |
| `kinetic-dns` | Recursive `.kin` resolver + split-DNS + cache | Not a trust boundary — must verify upstream of the cache |
| `kinetic-daemon` | Background service: local API (Axum), DNS, HTTP proxy, local CA | SSRF/rebinding, CA name-constraints, API auth, path handling |
| `kinetic-pac` | Proxy Auto-Configuration (PAC) server | Script injection, routing rules |
| `kinetic-kid` | DID documents + capability manifests (JCS-signed) | DID↔pubkey genesis binding, manifest version/`valid_from`, revocation |
| `kinetic-node` / `kinetic-host` | Infrastructure node & content-host runtimes | Static identity key file permissions (`0o600`) |
| `kinetic-wasm` | Browser/light-client WebAssembly build | Must verify VDF via `kyn-vdf`, not trust "N identical payloads" |
| `kinetic-cli` | User-facing name/identity/service commands | Key lifecycle, path building |
| `kinetic-forge` | Fork wizard: patch `network.json` + build custom binaries | Beacon scheme (https), network-id entropy |
| `kinetic-test` | Workspace integration testing suite | Multi-node test harness, failure injection |

---

## 3. Core flows

### 3.1 Name registration (commit / reveal + VDF)

1. **Commit:** the registrant publishes a hash commitment binding the name and
   their key, timestamped against a drand kyn. This prevents front-running the
   plaintext name.
2. **Compute:** the registrant runs the VDF for the required number of iterations,
   using a challenge derived from the drand randomness. This is the "cost."
3. **Reveal:** the registrant publishes the plaintext name, key, and VDF proof.
   Nodes **verify the VDF and signatures before accepting** the record into the
   DHT. This binding (name ↔ key ↔ proof-of-time) is what replaces a registrar fee.
4. **Heartbeat / renewal:** periodic signed broadcasts keep the record live; a
   watchtower can maintain heartbeats on the owner's behalf using pre-signed
   messages.

> **Trust boundary:** record *ingestion* verification (`store` +
> `event_loop`) is the line between untrusted network input and accepted state.
> All CPU-heavy verification here must run off the async reactor.

### 3.2 Resolution

- Local daemon receives a `.kin` query (DNS, proxy, or API), does a DHT lookup
  (or redundant multi-key lookup for reliability), verifies the returned Reveal,
  parses the `DnsZone`/records, and answers. Non-`.kin` DNS is forwarded upstream.
- **Light clients (wasm/mobile)** that cannot run the VDF must still obtain a
  cryptographic guarantee — not merely "several peers returned the same bytes."

### 3.3 Identity (KID) and the data-portability model

- A `did:kin:<hex>` is bound as `hex == sha256(primary_controller_pubkey)`. To control a
  DID you must hold the matching private key; a signature over the JCS-canonical
  document (signature field omitted) proves it. This blocks DID hijacking.
- **Capability manifests** are versioned service advertisements signed by a
  controller key and pointed to from the KID. They must enforce monotonic
  `version` and `valid_from` to prevent rollback.
- **Data ownership:** because identity + storage are anchored to the user's KID
  rather than an app server, app state (posts, likes, etc.) is portable — if an
  app dies, the user re-registers in a new app and re-attaches the same data.

### 3.4 Governance (public `.kin`, sovereign engine)

- State machine in `kinetic-core/src/governance/` with pluggable engines:
  `sovereign` (default) and `permissionless` (immutable).
- Modes: **Sovereign** is controlled exclusively by the offline Root key.
  **Permissionless** disables governance completely.
- Actions are ML-DSA-65-signed with canonical, domain-separated bytes.
  Emergency actions (`EmergencyHalt` / `EmergencyResume`) require the Root key and execute immediately upon signature verification.
- **Design note:** without a global blockchain, this cryptographic signature logic is
  what carries the weight a chain's finality would otherwise provide. It must be
  airtight — see the security checklist.

---

## 4. Configuration & forking

- `network.json` (repo root) → parsed by `build.rs` → `network_constants.rs` →
  `include!`d by `kinetic-core/src/constants.rs`.
- Governance/timing constants (`MAX_AGE_KYNS`,
  `CONSENSUS_MINIMUM_COMMIT_AGE_KYNS`, `STEAL_TARGET_KYNS`, `M_REDUNDANCY`, …) live directly in
  `network.json` and are compiled into `constants.rs`.
- **Governance root key** is `ROOT_PUBLIC_KEY_HEX`. In production builds, the verified ML-DSA-65 root key is pinned and checked via SHA-256 fingerprint in unit tests (`prod_keys::ROOT_PUBLIC_KEY_HEX`).
- `kinetic-forge` automates a fork: it rewrites `network.json` (NSP, DID prefix,
  drand config, etc.) and runs a release build.

---

## 5. Clients & SDKs

- **Desktop client** (Tauri): one-click install of
  the daemon + CLI + `kinetic-dns` for normal users `(Source: /home/saif/kinetic-desktop/src-tauri)`. Company/infra operators are
  expected to run their own setup.
- **Mobile app** (Android): native GeckoView browser + in-process Rust JNI node `(Source: /home/saif/kinetic-android)`.
- **Browser extension**: WebAssembly light client with Chrome MV3 DNR & Firefox WebRequest `(Source: /home/saif/kinetic-extension)`.
- **SDKs** (Rust + TypeScript) are generated from a hand-written OpenAPI spec
  (~17 endpoints) via openapi-generator — kept hand-written to avoid polluting the
  server code with generator macros `(Source: /home/saif/kinetic-sdk)`.

---

## 6. Ports (reference deployment)

| Purpose | Daemon | Node | Host |
|---------|--------|------|------|
| P2P (TCP / QUIC) | 6070 | 6071 | 6072 |
| Local API | 16002 | 16003 | 16004 |
| HTTP Reverse Proxy | 17001 | — | — |
| DNS Resolver | 53 | — | — |
| PAC Server | 16001 | — | — |
| Local Backend | 80 | — | — |
| Atlas Bridge (UDP) | 34291 | — | — |

---

## 7. Where to start reading (for auditors)

1. `kinetic-network/src/event_loop/` and `kinetic-network/src/store/` — the
   untrusted-input → accepted-state boundary.
2. `kinetic-core/src/drand.rs` — randomness binding `(Source: kinetic-core/src/drand.rs:120-126)`.
3. `kinetic-core/src/governance/` — the state machine + engines `(Source: kinetic-core/src/governance/engine/sovereign.rs)`.
4. `kinetic-daemon/src/proxy.rs` and `kinetic-dns/` — SSRF/rebinding surface.
5. `kinetic-kid/` — identity + manifest verification.
6. `kinetic-vdf/` — the only significant `unsafe`/FFI surface `(Source: kinetic-vdf/src/lib.rs)`.
7. `kinetic-verify/` / `kyn-vdf` — pure Rust Class Group arithmetic and verification.
