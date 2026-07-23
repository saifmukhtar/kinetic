# Kinetic — Architecture
 
This document explains how Kinetic is put together, so a new contributor (or an
auditor) can navigate the codebase and understand where trust boundaries lie.
 
Kinetic is an **engine**: the public `.kin` network is the reference deployment,
but every network-defining value (TLD, DID prefix, governance model, drand beacon,
bootstrap nodes, cost parameters) is read from `network.json` at build time and
baked into constants by `build.rs`. Forks change `network.json` and recompile.
 
---
 
## 1. High-level picture
 
```
                        ┌───────────────────────────────────────────┐
   user / app           │                kinetic-daemon              │
  ┌───────────┐  HTTP   │  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
  │  client   │────────▶│  │ local API│  │ split-DNS│  │  proxy   │  │
  │ (Tauri /  │  :API   │  │ (Axum)   │  │  :53     │  │  :5463   │  │
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
                        │   │kinetic-vdf │   │kinetic-store│          │
                        │   │(Chia FFI)  │   │ (sled KV)   │          │
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
| `kinetic-core` | Shared types, config, name rules, drand client, governance state machine + engines | Randomness binding, quorum/timelock logic, `is_valid_apex_name`, canonical signing bytes |
| `kinetic-vdf` | Rust bindings to Chia's C++ VDF | `unsafe` FFI, discriminant handling, proof verification |
| `kinetic-network` | libp2p swarm, Kademlia DHT, record store + validation, PoW, event loop | Inbound `PutRecord` validation, PoW checks, spawn_blocking placement, bounded maps |
| `kinetic-storage` | Persistence abstraction over `sled` (native) / in-memory (wasm) | Corruption recovery, cache-vs-authoritative separation |
| `kinetic-dns` | Recursive `.kin` resolver + split-DNS + cache | Not a trust boundary — must verify upstream of the cache |
| `kinetic-daemon` | Background service: local API (Axum), DNS, HTTP proxy, local CA | SSRF/rebinding, CA name-constraints, API auth, path handling |
| `kinetic-kid` | DID documents + capability manifests (JCS-signed) | DID↔pubkey binding, manifest version/`valid_from`, revocation |
| `kinetic-node` / `kinetic-host` | Infrastructure node & content-host runtimes | Static identity key file permissions |
| `kinetic-wasm` | Browser/light-client build | Must verify VDF, not trust "N identical payloads" |
| `kinetic-cli` | User-facing name/identity/service commands | Key lifecycle, path building |
| `kinetic-forge` | Fork wizard: patch `network.json` + build custom binaries | Beacon scheme (https), network-id entropy |
| `kinetic-keygen` | Key generation helper | Secure RNG + `0o600` |
 
---
 
## 3. Core flows
 
### 3.1 Name registration (commit / reveal + VDF)
 
1. **Commit:** the registrant publishes a hash commitment binding the name and
   their key, timestamped against a drand round. This prevents front-running the
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
 
- A `did:kin:<hex>` is bound as `hex == sha256(controller_pubkey)`. To control a
  DID you must hold the matching private key; a signature over the JCS-canonical
  document (signature field omitted) proves it. This blocks DID hijacking.
- **Capability manifests** are versioned service advertisements signed by a
  controller key and pointed to from the KID. They must enforce monotonic
  `version` and `valid_from` to prevent rollback.
- **Data ownership:** because identity + storage are anchored to the user's KID
  rather than an app server, app state (posts, likes, etc.) is portable — if an
  app dies, the user re-registers in a new app and re-attaches the same data.
 
### 3.4 Governance (public `.kin`, bicameral)
 
- State machine in `kinetic-core/src/governance/` with pluggable engines:
  `monarchy`, `council`, `bicameral` (default), `anarchy` (immutable).
- Modes: **Founder → Council**, with an auto-lock after
  `AUTO_LOCK_SECONDS` (1 year) and instant lock when ≥ `MIN_ACTIVE_COUNCIL` (7)
  active members + a guard key exist. `MAX_COUNCIL_SIZE` is 21.
- Actions are Ed25519-signed with canonical, domain-separated bytes. Council
  actions require percentage quorums (69/90/95%); OTA binary updates carry a
  timelock (`OTA_TIMELOCK_SECONDS`, 48h) with a guard veto window;
  `EmergencyReset` requires root (and normally guard) and is timelocked.
- **Design note:** without a global blockchain, this quorum + timelock logic is
  what carries the weight a chain's finality would otherwise provide. It must be
  airtight — see the security checklist.
 
---
 
## 4. Configuration & forking
 
- `network.json` (repo root) → parsed by `build.rs` → `network_constants.rs` →
  `include!`d by `kinetic-core/src/constants.rs`.
- Governance/timing constants (`MIN_ACTIVE_COUNCIL`, `MAX_AGE_SECONDS`,
  `OTA_TIMELOCK_SECONDS`, `ACTIVE_WINDOW_SECONDS`, …) live directly in
  `constants.rs`.
- **Governance root/guard keys** are `ROOT_PUBLIC_KEY_HEX` /
  `GUARD_PUBLIC_KEY_HEX`. The production build ships placeholders
  (`REPLACE_ME_OFFLINE_GENERATED_*`) — a real T0 deployment MUST replace these
  with offline-generated keys before building.
- `kinetic-forge` automates a fork: it rewrites `network.json` (TLD, DID prefix,
  drand config, etc.) and runs a release build.
 
---
 
## 5. Clients & SDKs
 
- **Desktop / mobile / browser-extension client** (Tauri): one-click install of
  the daemon + CLI + `kinetic-dns` for normal users `(Source: /home/saif/kinetic-client/desktop/src-tauri)`. Company/infra operators are
  expected to run their own setup.
- **SDKs** (Rust + TypeScript) are generated from a hand-written OpenAPI spec
  (~17 endpoints) via openapi-generator — kept hand-written to avoid polluting the
  server code with generator macros.
 
---
 
## 6. Ports (reference deployment)
 
| Purpose | Daemon | Node | Host |
|---------|--------|------|------|
| P2P | 6070 | 6071 | 6072 |
| Local API | 16002 | 16003 | 16004 |
| Proxy | 5463 | — | — |
| DNS | 53 | — | — |
 
---
 
## 7. Where to start reading (for auditors)
 
1. `kinetic-network/src/event_loop/` and `kinetic-network/src/store/` — the
   untrusted-input → accepted-state boundary.
2. `kinetic-core/src/drand.rs` — randomness binding `(Source: kinetic-core/src/drand.rs:121)`.
3. `kinetic-core/src/governance/` — the state machine + engines `(Source: kinetic-core/src/governance/engine/bicameral.rs)`.
4. `kinetic-daemon/src/proxy/` and `kinetic-dns/` — SSRF/rebinding surface.
5. `kinetic-kid/` — identity + manifest verification.
6. `kinetic-vdf/` — the only significant `unsafe`/FFI surface `(Source: kinetic-vdf/src/lib.rs)`.
