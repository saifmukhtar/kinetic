# Kinetic Protocol — Security & Optimization Audit

**Auditor role:** Principal Security Architect / Decentralized Systems Engineer
**Scope:** `kinetic-core`, `kinetic-vdf`, `kinetic-network`, `kinetic-daemon`, `kinetic-host`, `kinetic-node`, `kinetic-cli`, `kinetic-kid`, `kinetic-dns`, `kinetic-storage`, `kinetic-wasm` (Rust, ~25k LOC / 175 files).
**Method:** Manual line-by-line review of security-critical paths (crypto, DHT record ingestion, VDF/consensus, P2P swarm event loop, proxy/SSRF, CA, key management, drand). Findings below are concrete and cite exact locations. A coverage note appears at the end.

Threat model assumption: the network is under active attack by a well-resourced adversary who can run many nodes, control DNS for seizable seed domains, and MITM plaintext traffic.

---

## Executive summary of the worst issues

| # | Severity | Location | One-liner |
|---|----------|----------|-----------|
| 1 | **CRITICAL** | `kinetic-network/src/event_loop/swarm_handler.rs:226` | Inbound DHT `PutRecord` is VDF-verified **synchronously on the swarm event-loop task** → reactor starvation / whole-node freeze under a PutRecord flood. |
| 2 | **CRITICAL** | `kinetic-network/src/event_loop/swarm_handler.rs:136` | 16 MB Argon2id PoW check runs **inline on the async task** for every `ConnectionEstablished` → connection-flood memory+CPU DoS. |
| 3 | **HIGH** | `kinetic-core/src/drand.rs:72` | `DrandPulse::verify()` validates the BLS signature over the round but **never binds `randomness` to the signature** → a malicious endpoint returns a valid old signature with attacker-chosen randomness. |
| 4 | **HIGH** | `kinetic-core/src/drand.rs:148` | Drand endpoints are injected from **DNS TXT records over plaintext DNS** with no allow-list → endpoint hijack + centralization/seizure vector; amplifies #3. |
| 5 | **HIGH** | `kinetic-network/src/pow.rs:8` | Sybil PoW difficulty is **8 bits (~256 tries)** → Sybil/Eclipse protection is effectively absent. |
| 6 | **HIGH** | `kinetic-network/src/event_loop/utils.rs:311` | Light clients (`UnsupportedPlatform`) accept a Reveal on **3 identical payloads with no VDF check** → DHT poisoning of wasm/Android clients (trivial given #5). |
| 7 | **HIGH** | `kinetic-node/src/identity.rs:22`, `kinetic-host/src/identity.rs:14` | Infrastructure Ed25519 **private keys written world-readable** (default 0644, no `0o600`). |

---

## 1. Cryptographic & Identity Security

### [CRITICAL] Drand `randomness` is not bound to the verified signature
- **[LOCATION]** `kinetic-core/src/drand.rs:72-102` (`DrandPulse::verify`) and `:194-221` (`fetch_with_backoff`)
- **[VULNERABILITY]** For Quicknet (unchained), `randomness == SHA-256(signature)`. `verify()` only calls `pk.verify(self.round, &[], &sig_bytes)` — it validates the signature over the round number, but the `randomness` string is deserialized straight from the endpoint's JSON and is **never recomputed/compared** against `SHA-256(signature)`. The VDF registration challenge is `SHA-256(name‖salt‖randomness‖pubkey)` (see `kinetic-daemon/src/api/vdf.rs:141-151` and `store/verification.rs:246-253`), so the value that seeds every proof is attacker-influenceable.
- **[EXPLOIT SCENARIO]** A compromised/malicious drand endpoint (or one injected via finding #4, or a replay of any historical `(round, signature)` pair) returns a *valid* signature but a *bogus* `randomness`. `verify()` passes. All nodes now compute/accept VDFs against attacker-chosen randomness, defeating the unpredictability the beacon is supposed to provide (front-running lottery, `steal_difficulty`, tie-breaks).
- **[REMEDIATION CODE]** Bind randomness to the signature inside `verify()`:
```rust
pub fn verify(&self) -> bool {
    if self.is_unavailable { return true; }
    if crate::config::is_dev_mode() { return true; }

    let pubkey_bytes: [u8; 96] = match hex::decode(crate::constants::DRAND_PUBLIC_KEY)
        .ok().and_then(|b| b.try_into().ok()) { Some(b) => b, None => return false };
    let pk = match G2PubkeyRfc::from_fixed(pubkey_bytes) { Ok(p) => p, Err(_) => return false };
    let sig_bytes = match hex::decode(&self.signature) { Ok(b) => b, Err(_) => return false };

    // 1. Verify BLS signature over the round (Quicknet is unchained).
    if !pk.verify(self.round, &[], &sig_bytes).unwrap_or(false) { return false; }

    // 2. Bind the randomness to the signature: randomness MUST equal SHA-256(signature).
    use sha2::{Digest, Sha256};
    let expected = Sha256::digest(&sig_bytes);
    match hex::decode(&self.randomness) {
        Ok(r) => r.as_slice() == expected.as_slice(),
        Err(_) => false,
    }
}
```

### [HIGH] Infrastructure private keys are written world-readable
- **[LOCATION]** `kinetic-node/src/identity.rs:20-25`, `kinetic-host/src/identity.rs:12-17`
- **[VULNERABILITY]** `std::fs::write(key_path, encoded)` persists the libp2p Ed25519 **secret** protobuf with the process umask (typically `0644`). Unlike `kinetic-core/src/types/identity.rs:126-137` (which correctly uses a temp file + `mode(0o600)` + rename) these paths have no permission hardening. `kinetic-host/src/bin/get_pub.rs:5-7` confirms the raw secret sits on disk.
- **[EXPLOIT SCENARIO]** Any local user (or a compromised low-priv process) reads the node/host identity key, then impersonates the infrastructure node's PeerId — hijacking `HostRoutingRecord` routing and any name that trusts that identity.
- **[REMEDIATION CODE]** (apply to both files)
```rust
} else {
    let k = Keypair::generate_ed25519();
    if let Ok(encoded) = k.to_protobuf_encoding() {
        if let Err(e) = write_secret(key_path, &encoded) {
            tracing::warn!("Failed to save static infrastructure identity: {}", e);
        }
    }
    tracing::info!("Generated new static infrastructure identity");
    k
}

#[cfg(unix)]
fn write_secret(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(tmp, path) // atomic; avoids leaving a partial world-readable key
}
#[cfg(not(unix))]
fn write_secret(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes) // TODO: harden ACLs on Windows via icacls
}
```

### [POSITIVE / LOW] Good crypto hygiene worth preserving
- `save_keypair_from_mnemonic` (`kinetic-core/src/types/identity.rs:89-137`) uses PBKDF2-HMAC-SHA512 @ 600k iterations, zeroizes intermediates, temp-file + `0o600` + `sync_all`. Keep this as the template.
- API token: `getrandom::fill` (fails **closed** if RNG fails), `0o600`, constant-time compare via `subtle::ct_eq` with an explicit equal-length guard (`kinetic-daemon/src/api/mod.rs:146-178, 243-285`). Correct.
- **[LOW risk]** Single point of collapse: `is_dev_mode()` is compile-time (`cfg!(feature = "simulation")`, `config.rs:277-279`) — good, it cannot be flipped at runtime. But that one feature disables commitment checks, VDF verification, PoW, signature-freshness and routability filters simultaneously (`store/verification.rs:255,296`, `pow.rs:50`, `utils.rs:54`). Ensure `simulation` can never be enabled transitively in a release dependency graph; add a `compile_error!` guard if `simulation` + `release` are both set.

### [MEDIUM] VDF discriminant strength & asymmetric derivation
- **[LOCATION]** `kinetic-vdf/src/lib.rs:83-127`
- **[VULNERABILITY]** The class-group discriminant is **1024-bit** (`chiavdf::prove(&hash, .., 1024, ..)`). 1024 bits is chiavdf's test/demo size; Chia mainnet uses 2048-bit discriminants because sub-1024-bit class-group discriminants are within reach of well-funded adversaries and weaken the sequentiality guarantee. Separately, `evaluate` lets `chiavdf::prove` derive the discriminant internally from the raw hash while `verify` derives it via `create_discriminant`; correctness relies on both deriving identically (guarded only by a single golden-value test at `:247`).
- **[EXPLOIT SCENARIO]** An adversary who can factor/attack a 1024-bit discriminant class group could shortcut the "delay," defeating the time-lock and enabling instant domain sniping/steals that are supposed to require days of sequential compute.
- **[REMEDIATION]** Move to a 2048-bit discriminant and pin it as a protocol constant used by *both* code paths:
```rust
pub const KINETIC_VDF_DISCRIMINANT_BITS: usize = 2048;
// evaluate:
chiavdf::prove(&challenge.hash, &default_el, KINETIC_VDF_DISCRIMINANT_BITS as i32, iterations)
// verify:
let mut disc = [0u8; KINETIC_VDF_DISCRIMINANT_BITS / 8];
if !chiavdf::create_discriminant(&challenge.hash, &mut disc) { return Err(VdfError::DiscriminantError); }
```
(Note: this is a consensus-breaking change — version-gate it.)

---

## 2. Peer-to-Peer & Network Threats

### [CRITICAL] Synchronous VDF verification on the swarm event loop (reactor starvation)
- **[LOCATION]** `kinetic-network/src/event_loop/swarm_handler.rs:218-231` → `store/core.rs:238-371` (`put_record`) → `store/handlers.rs:20-28` → `store/verification.rs:317` (`engine.verify` = chiavdf C++)
- **[VULNERABILITY]** `InboundRequest::PutRecord` calls `store_mut().put_record(record)` **directly inside `handle_swarm_event`**, which is the single async task driving the whole libp2p `Swarm`. `put_record` performs signature checks, sled reads, and a **synchronous chiavdf verification** — all CPU/FFI work with no `spawn_blocking`. The resolution read path was correctly offloaded (`handle_get_completion:57-61`), but the **ingestion path was not**.
- **[EXPLOIT SCENARIO]** An attacker streams `PutRecord`s carrying well-formed Reveals. Each forces a synchronous VDF verify on the reactor thread; while it runs, no other swarm events (dials, Kademlia queries, heartbeats, proxy streams) are serviced. A modest inbound rate freezes the node — a cheap, targeted DoS that also stalls every pending user query.
- **[REMEDIATION CODE]** Offload verification; only touch the store on the loop for the final insert. Sketch:
```rust
kad::InboundRequest::PutRecord { source, record: Some(record), .. } => {
    let engine = self.vdf_engine.clone();
    let storage = self.store_snapshot_handle(); // Arc, cheap
    let drand = self.current_drand_pulse;
    let cmd_tx = self.self_tx.clone(); // loopback channel into the event loop
    crate::event_loop::utils::spawn(async move {
        let verdict = crate::event_loop::utils::spawn_blocking(move || {
            verify_record_offloaded(&record, &storage, drand, &engine) // pure verify, no &mut self
        }).await;
        // Send only the *decision* back to the loop; the loop does the O(1) insert/ban bookkeeping.
        let _ = cmd_tx.send(NetworkCommand::CommitVerifiedRecord { source, record, verdict }).await;
    });
}
```
Even a coarser fix — bounding concurrent inbound verifications with a `Semaphore` and running each under `spawn_blocking` — removes the head-of-line blocking.

### [CRITICAL] 16 MB Argon2 PoW verification runs inline on the async task
- **[LOCATION]** `swarm_handler.rs:136` (`self.is_valid_pow(&peer_id)` on `ConnectionEstablished`), `:380` (on `Identify`), `:422` (on mDNS); `pow.rs:49-80` allocates 16 MB + runs Argon2id per call (up to twice).
- **[VULNERABILITY]** `is_valid_sybil_pow` is not offloaded. Every inbound connection triggers a 16 MB allocation and one-to-two Argon2id hashes **on the reactor**.
- **[EXPLOIT SCENARIO]** Connection flood → repeated 16 MB allocations and Argon2 CPU on the event-loop thread → memory pressure + starvation. The defender pays 16 MB+Argon2 per *connection attempt* while the attacker pays only a TCP/QUIC handshake. Amplification favors the attacker.
- **[REMEDIATION]** Gate new connections through a bounded `spawn_blocking` PoW check *before* admitting them, cache the verdict per PeerId per epoch (so repeat connections don't re-hash), and rate-limit inbound handshakes (libp2p `ConnectionLimits`). `.expect("Argon2 memory allocation failed…")` at `pow.rs:30` should also become a graceful `false`, never a panic on the loop.

### [HIGH] Sybil PoW difficulty is trivially low
- **[LOCATION]** `kinetic-network/src/pow.rs:8` (`DEFAULT_DIFFICULTY_BITS: u32 = 8`)
- **[VULNERABILITY]** 8 leading zero bits ⇒ ~256 Argon2 attempts (seconds) to mint a valid epoch identity. With a 12h epoch and previous-epoch grace, an attacker can pre-mine thousands of valid PeerIds.
- **[EXPLOIT SCENARIO]** Eclipse attack: flood the victim's Kademlia routing table (added at `swarm_handler.rs:392-407`) and the quorum/tie-break resolution with Sybil identities, then feed poisoned records. Cheap enough to sustain continuously.
- **[REMEDIATION]** Raise difficulty to a memory-bound cost that is expensive to grind but cheap to verify once (e.g. 20-24 bits), make it configurable, and scale it with observed churn. Verify cost must be paid off-reactor (see above). Consider binding identity PoW to the connection challenge, not just the epoch, to prevent pre-mining pools.

### [HIGH] Light-client VDF bypass via 3-identical-payload "quorum"
- **[LOCATION]** `kinetic-network/src/event_loop/utils.rs:311-330`
- **[VULNERABILITY]** On `VdfError::UnsupportedPlatform` (wasm32/Android) the tie-breaker accepts a Reveal if **≥3 byte-identical payloads** were received, with no VDF and no per-peer identity check. Given the 8-bit Sybil cost (#5), producing 3 responders is free.
- **[EXPLOIT SCENARIO]** Attacker runs ≥3 Sybil nodes that all answer a light client's `GetRecord` with the same forged Reveal → the client resolves `did:kin`/domain to attacker-controlled data. Full DHT poisoning of the entire mobile/web client population.
- **[REMEDIATION]** Do not bypass cryptographic verification with response-count consensus. For platforms that cannot run chiavdf, verify VDFs via a WASM/pure-Rust class-group verifier, or require the client to fetch from ≥N *distinct, PoW-qualified* peers **and** verify Ed25519 signatures + commitment linkage (which don't need chiavdf) before trusting; treat unverifiable VDFs as unresolved, not "trusted after 3 copies."

### [HIGH] Drand endpoint injection via plaintext DNS TXT (centralization/seizure)
- **[LOCATION]** `kinetic-core/src/drand.rs:146-159` (+ config default `drand.<BASE_DOMAIN>` at `config.rs:74-76`)
- **[VULNERABILITY]** Any `https://` URL found in a TXT record of a configured seed domain is appended to the endpoint list, unbounded and unauthenticated. The lookup uses the system resolver (plaintext DNS, `DrandClient::new` at `drand.rs:130-133`).
- **[EXPLOIT SCENARIO]** A nation-state that seizes the seed domain, or an on-path attacker spoofing DNS, injects their endpoint. Combined with #3 (randomness unbound), they now feed chosen randomness that still passes `verify()`. Single-domain dependency is also a decentralization/SPOF.
- **[REMEDIATION]** Only accept endpoints whose responses are validated by #3's signature+randomness binding (which makes endpoint trust moot); cap the number of injected endpoints; use DNSSEC/DoH for the TXT lookup; and treat seed domains as *hints* for reachability only, never as trust anchors.

### [MEDIUM] Ban list is fully wiped at capacity → ban evasion & state divergence
- **[LOCATION]** `swarm_handler.rs:243-266` (esp. `:253-255`)
- **[VULNERABILITY]** When `banned_peers.len() >= 10_000` the entire in-memory map is `clear()`ed, and the per-peer persisted ban keys (`kinetic_banned_peer:*`) are not reconciled. An attacker who trips 10k bans (cheap given #5) flushes all existing bans.
- **[EXPLOIT SCENARIO]** Sustained bad-record spam from disposable Sybils both evicts legitimately-banned peers and desyncs memory vs. sled state (bans persist on disk but not in memory, or vice-versa).
- **[REMEDIATION]** Use an LRU/TTL-bounded structure and evict the **oldest/soonest-to-expire** entries individually; keep the persisted store authoritative and lazily load on connect. Never mass-`clear()`.

### [MEDIUM] Unbounded `bad_vdf_counts` map
- **[LOCATION]** `swarm_handler.rs:236` (`self.bad_vdf_counts.entry(source).or_insert(...)`)
- **[VULNERABILITY]** One entry per offending `source`; never pruned. Sybils create unbounded entries.
- **[REMEDIATION]** Bound with an LRU capacity and drop entries whose 60s window has elapsed.

### [MEDIUM] Quorum match-count is Sybil-inflatable
- **[LOCATION]** `swarm_handler.rs:150-158` (`pending.match_count += 1` per matching `FoundRecord`)
- **[VULNERABILITY]** "Quorum" counts matching records with no de-duplication by verified identity/PoW; an attacker with many Sybils inflates the count for a forged payload.
- **[REMEDIATION]** Count distinct PoW-qualified responders and require cryptographic validity of the payload before counting; don't treat popularity as correctness.

### [MEDIUM] Record-type dispatch by JSON field probing (type confusion)
- **[LOCATION]** `store/core.rs:256-353`
- **[VULNERABILITY]** The record kind is inferred by presence of keys (`hash`/`vdf_proof`/`latest_drand_pulse`/`delegation_signature`/`manifest`/`host_id`) on an untyped `serde_json::Value`, using `#[serde(...)]` structs that likely don't `deny_unknown_fields`. A crafted object matching an earlier branch is parsed as that type. Each type is independently verified so it's not directly forgeable, but it's brittle and invites future bypasses.
- **[REMEDIATION]** Use a single internally-tagged enum and reject unknown fields:
```rust
#[derive(Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum DhtRecord {
    Commitment(Commitment), Reveal(Reveal), Heartbeat(Heartbeat),
    AuthorizedKid(AuthorizedKid), AuthorizedManifest(AuthorizedManifest), HostRouting(HostRoutingRecord),
}
```

### [MEDIUM] Local API is exposed to DNS-rebinding; CORS allows any browser extension
- **[LOCATION]** `kinetic-daemon/src/api/mod.rs:74-99` (CORS predicate) and `:130-141` (public unauthenticated routes)
- **[VULNERABILITY]** The API binds to loopback and the mutating routes require a bearer token (good), but (a) there is **no `Host` header allow-list**, so a malicious site using DNS-rebinding to `127.0.0.1` can hit the unauthenticated `resolve/network-status/zone GET` routes; (b) CORS reflects **any** `chrome-extension://`/`moz-extension://` origin.
- **[REMEDIATION]** Add a `Host`-header guard middleware (only `localhost`/`127.0.0.1`/`[::1]` with the known port); pin the extension IDs you actually ship rather than any-extension prefixes.

### [LOW] P2P proxy path-traversal filter is incomplete
- **[LOCATION]** `kinetic-daemon/src/proxy/p2p.rs:24`
- **[VULNERABILITY]** `req.path.contains("..")` blocks literal `..` but not URL-encoded traversal (`%2e%2e%2f`) or overlong-encoded variants; the encoded form is forwarded to the local backend.
- **[REMEDIATION]** Percent-decode once, reject if the decoded path contains `..` or does not start with `/`, and forward the normalized path.

### [POSITIVE] Good P2P hardening already present
- ProviderRecords globally disabled to prevent provider spam (`store/core.rs:394-397`); 80 KB record cap (`:245`); non-routable multiaddrs filtered (`utils.rs:53-92`); heartbeat monotonicity + future-date rejection (`handlers.rs:196-217`); host-route timestamp freshness window (`verification.rs:11-40`).

---

## 3. Concurrency, Memory Safety & State

### [HIGH] (see §2) CPU/FFI work on the reactor — findings #1 and #2 are the dominant concurrency bugs.

### [LOW] `spawn_blocking` unwraps the JoinHandle
- **[LOCATION]** `kinetic-network/src/event_loop/utils.rs:49` (`tokio::task::spawn_blocking(f).await.unwrap()`)
- **[VULNERABILITY]** If the blocking closure panics (e.g. a chiavdf edge case), `.unwrap()` turns it into a panic in the spawning task.
- **[REMEDIATION]** Return `Result` and handle `JoinError` gracefully (log + treat as verification failure) instead of `unwrap()`.

### [LOW] VDF global filesystem lock serializes all evaluations
- **[LOCATION]** `kinetic-vdf/src/lib.rs:56-81`
- **[VULNERABILITY / PERF]** A single system-wide exclusive `flock` on `kinetic_vdf.lock` is held for the entire evaluation. On a multi-core box this prevents parallel proofs (wastes cores), and any local process can hold the lock to stall the daemon's registrations (local DoS). `O_NOFOLLOW` is good; the coarse serialization is the issue.
- **[REMEDIATION]** Replace the file lock with an in-process concurrency limiter sized to `min(available_parallelism, N)` (a `Semaphore`), so independent proofs can use separate cores while still bounding total CPU. The API layer already has a `vdf_semaphore` — unify on that rather than a cross-process file lock.

### [MEDIUM] TOCTOU / cross-process race in the CA lock
- **[LOCATION]** `kinetic-daemon/src/ca.rs:47-67` and `:149`
- **[VULNERABILITY]** After 100 retries the code `remove_file`s the lock unconditionally (assuming staleness), then loops; and on completion it `remove_file`s the lock unconditionally. Two racing daemons can each delete the other's lock and both enter the "generate new CA" section, or one can delete a lock the other legitimately holds.
- **[EXPLOIT SCENARIO]** Concurrent daemon starts (or an attacker touching the lock file) cause two CA generations racing on the same `ca_cert.pem`/`ca_key.pem`, risking a torn/overwritten key file.
- **[REMEDIATION]** Use an advisory OS lock (`fs2::FileExt::lock_exclusive` on a dedicated lock file that is never deleted) instead of `create_new` + timed force-remove; only the lock *holder* releases it (drop the handle), never a blind `remove_file`.

---

## 4. File System & OS Exploits

- **[MEDIUM]** World-readable identity keys — covered in §1 (`node/identity.rs`, `host/identity.rs`).
- **[MEDIUM]** CA lock TOCTOU — covered in §3 (`ca.rs`).
- **[LOW / POSITIVE]** `kinetic-vdf/src/lib.rs:69-73` uses `O_NOFOLLOW` on the lock file (symlink-swap resistant) — keep it, and apply the same to other predictable-path opens under the data dir.
- **[LOW]** `kinetic-daemon/src/api/mod.rs:192-201` reuses an on-disk API token if it is 64 chars but does not re-check the file's mode on load; a token file that was created world-readable earlier (or by another tool) is trusted. Verify `0o600` on load and regenerate if the perms are wrong.

---

## 5. Architectural Decentralization

- **[HIGH]** Seed-domain trust for drand endpoints (`drand.rs:146-159`) and for P2P bootstrap discovery (`config.rs:154-156, 204`) creates seizable single domains. Bootstrap nodes are also a hardcoded default set (`config.rs:200-203`) — mitigated by mDNS + `seed_domains`, but the *default trust* still funnels through nation-state-seizable DNS.
- **[REMEDIATION]** (a) Make endpoint/bootstrap trust cryptographic, not DNS-based (finding #3/#4 fixes drand; for bootstrap, ship multiaddrs that include the `/p2p/<peerid>` component so a seized DNS record cannot substitute a different node). (b) Support multiple independent seed domains across TLDs/operators and require agreement, or sign the seed payloads. (c) Persist and gossip a peer cache so a node that has run once never needs the seed domains again.

---

## 6. Extreme Optimization

- **[OPTIMIZATION]** `event_loop/utils.rs:101` clones the entire payload vector (`_original_payloads = payloads.clone()`) purely to later `.iter().filter(...).count()` for the UnsupportedPlatform branch (`:312`), then `:111` moves payloads into a `HashSet` (another full pass + allocations). On the hot resolution path this is 2× the payload memory. Keep a single `Vec`, dedup in place (`sort_unstable` + `dedup`) and compute the count from it; drop the `.clone()`.
- **[OPTIMIZATION]** `store/handlers.rs:132-133` does `reveals_by_name.put(reveal.name.clone(), reveal.clone())` and re-serializes (`:138`) on every accepted reveal. Pass ownership where possible and serialize once; avoid the double allocation of name + full struct per put.
- **[OPTIMIZATION]** `ca.rs:239-247` evicts by scanning `entries.iter().min_by_key(...)` — O(n) per insert. Use an actual LRU (e.g. the `lru` crate already used in `kinetic-network`) for O(1) eviction.
- **[OPTIMIZATION]** `store/core.rs:111` restores heartbeats with `scan_prefix(KRS_HB_PREFIX, None)` (unbounded) while reveals are bounded at `:49`. A peer that flooded historical heartbeats can bloat startup memory; bound this scan symmetrically.
- **[OPTIMIZATION]** `proxy/http.rs:346-357` buffers the entire P2P proxy request body into a `Vec` (up to 5 MB) before forwarding; stream it instead to cut latency and peak memory on the proxy hot path.

---

## Coverage note

I performed deep manual review of the security-critical surface: `kinetic-vdf`, the `kinetic-network` DHT store + event loop (`store/*`, `event_loop/*`, `pow.rs`), `kinetic-core` (`config.rs`, `drand.rs`, `types/identity.rs`, consensus inputs), the `kinetic-daemon` proxy (`http.rs`, `p2p.rs`, `mod.rs`, `security.rs`, `tunnel.rs`), CA (`ca.rs`), and API (`api/mod.rs`, `api/vdf.rs`), plus key management across `kinetic-node`/`kinetic-host`. I did **not** exhaustively line-audit every one of the 175 files (e.g. governance engines, DNS resolver internals, WASM bindings, CLI subcommands, test/fuzz harnesses); the findings above are the high-confidence, verifiable ones. 
