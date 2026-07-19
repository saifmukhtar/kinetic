# Kinetic Protocol — Security Audit Addendum

Covers `kinetic-dns`, `kinetic-kid`, `kinetic-core::governance`, and `kinetic-wasm`. Same format as the main report; new findings are numbered #8+.

---

## kinetic-dns

### [HIGH] `.kin` resolution serves records with **no cryptographic verification at the DNS layer**
- **[LOCATION]** `kinetic-dns/src/kinetic_records.rs:83-136` (`resolve_kinetic`)
- **[VULNERABILITY]** The DNS handler fetches `GET {api_url}/api/resolve/{apex}`, `serde_json::from_slice::<Reveal>()`, and serves the zone's records. It performs **zero** signature/VDF/commitment checks itself — it fully trusts the daemon's public, unauthenticated `/api/resolve` endpoint (`kinetic-daemon/src/api/mod.rs:130-141`). Whatever that endpoint returns is cached for 5 minutes (`cache.rs:17`) and served as authoritative DNS.
- **[EXPLOIT SCENARIO]** Two amplifiers: (1) if the resolve endpoint's underlying DHT path is poisoned (see main-report findings #1/#5/#6, trivial on light clients), the poison is served as real DNS and cached 5 min per apex; (2) the `http_client` has no auth token and targets `api_url` — if `api_url` is ever non-loopback or a local attacker binds the port first, responses are spoofable. The DNS layer is a pure trust-forwarder with a 5-minute poison-persistence window.
- **[REMEDIATION]** Verify the `Reveal` signature (and, where the platform supports it, the VDF) **inside the DNS resolver** before caching/serving, and treat the daemon API strictly as loopback with an asserted `Host`/origin. At minimum, shorten positive TTL and bind `api_url` to `127.0.0.1` with a startup assertion:
```rust
// kinetic_records.rs, after deserializing the Reveal, before building records:
if !crate::verify_reveal_signature(&reveal) {           // Ed25519 over reveal.signable_bytes()
    warn!("Rejecting .kin resolution: reveal signature invalid for {}", apex_domain);
    let response = builder.error_msg(request.header(), hickory_proto::op::ResponseCode::ServFail);
    let _ = response_handle.send_response(response).await;
    header.set_response_code(hickory_proto::op::ResponseCode::ServFail);
    return header.into();
}
```

### [MEDIUM] SSRF filter drift between DNS and proxy — CGNAT / NAT64 / `0.0.0.0/8` gaps
- **[LOCATION]** `kinetic-dns/src/kinetic_records.rs:166-206` vs `kinetic-daemon/src/proxy/security.rs:1-60`
- **[VULNERABILITY]** The DNS A/AAAA SSRF filter is **reimplemented separately** from the proxy's `is_ssrf_risk` and is not in sync. The DNS A-record filter blocks loopback/unspecified/broadcast/multicast/private/link-local/documentation but **not** CGNAT `100.64.0.0/10` (which the proxy *does* block, and which routes to cloud metadata in many environments). Both filters also miss `0.0.0.0/8` (only the single `0.0.0.0` is caught by `is_unspecified`) and IPv6 NAT64 `64:ff9b::/96`.
- **[EXPLOIT SCENARIO]** A malicious `.kin` zone publishes `A 100.64.0.x` (or an all-zeros-prefixed `0.x.x.x`). A browser using this resolver connects to a CGNAT/link-adjacent internal host that the operator assumed was unreachable from `.kin` names — SSRF/rebinding-style pivot.
- **[REMEDIATION]** Delete the duplicated logic and call the single hardened classifier from both crates:
```rust
// promote is_ssrf_risk into kinetic-core (e.g. kinetic_core::net::is_forbidden_ip)
// and add the missing ranges:
if let std::net::IpAddr::V4(v4) = ip {
    let o = v4.octets();
    if o[0] == 0 { return true; }                       // 0.0.0.0/8
    if o[0] == 100 && (o[1] & 0xC0) == 64 { return true; } // 100.64.0.0/10 CGNAT
}
// IPv6 NAT64 64:ff9b::/96
if let std::net::IpAddr::V6(v6) = ip {
    let s = v6.segments();
    if s[0]==0x0064 && s[1]==0xff9b && s[2]==0 && s[3]==0 && s[4]==0 && s[5]==0 { return true; }
}
```
Then in `kinetic_records.rs` replace both bespoke A/AAAA checks with `kinetic_core::net::is_forbidden_ip(ip)`.

### [LOW] `.kin` DNS responses are unsigned plaintext (no DNSSEC)
- **[LOCATION]** `kinetic-dns/src/kinetic_records.rs` (whole path), server on UDP/TCP 53
- **[VULNERABILITY]** Responses for `.kin` carry no DNSSEC/RRSIG. Anything between the stub resolver and this server (localhost is fine, but LAN deployments exist) can tamper. Upstream non-`.kin` uses DoH fallback (`upstream.rs:20`), but `.kin` answers are as trustworthy as the transport.
- **[REMEDIATION]** Document that the resolver must run on loopback only; for non-loopback deployments, sign `.kin` answers (DNSSEC online-signing) or require DoT/DoH to the resolver.

### [POSITIVE] Good things in kinetic-dns
- Cache-stampede protection via moka `try_get_with` (`kinetic_records.rs:83`), bounded cache (10k, `cache.rs:53`), asymmetric TTL (30s negative), 5s HTTP timeout with graceful client fallback (`lib.rs:52-61`), and `PUBLIC_NAMES`/`localhost` interception preventing `.kin` shadowing of real infrastructure (`kinetic_records.rs:26-77`).

---

## kinetic-kid

### [POSITIVE] KID document verification correctly resists the classic DID-hijack
- **[LOCATION]** `kinetic-kid/src/document.rs:88-119`
- The signer's public key must hash (SHA-256) to the DID's method-specific-id (`hex_hash != method_specific_id → continue`), so an attacker cannot append their own controller key and self-sign. `controller_keys` is bounded to 20 (`:72`). Canonicalization is JCS (RFC 8785). `AuthorizedKid` ingestion chains both checks (`verify_authorized_kid` calls `kid_doc.verify()` **and** owner-signature verification — `store/verification.rs:361`). This is solid.

### [MEDIUM] `AuthorizedManifest` ingestion skips the manifest's own signature & DID binding
- **[LOCATION]** `kinetic-network/src/store/verification.rs:379-415` (`verify_authorized_manifest`) vs `kinetic-kid/src/manifest.rs:57-94`
- **[VULNERABILITY]** Unlike the KID path, `verify_authorized_manifest` verifies **only** `auth_manifest.owner_signature` (the domain owner's reveal key) over `signable_bytes()`. It never calls `CapabilityManifest::verify(&kid_document)` nor validates that the embedded `manifest.kid` matches an authenticated KID document. The DID-binding logic in `kinetic-kid` is effectively dead code on this ingestion path.
- **[EXPLOIT SCENARIO]** The domain owner (or anyone who compromises the domain's reveal key) can publish a `CapabilityManifest` whose `kid` field points at an arbitrary/other DID, or with an internally-inconsistent/absent manifest signature. Consumers that later trust `manifest.kid` as an authenticated DID→services binding are misled. It is not a *cross-owner* forgery (owner authority is still required), but the manifest's self-consistency guarantees are not enforced where the docs imply they are.
- **[REMEDIATION]** Mirror the KID path — require the inner manifest to verify against its KID document:
```rust
// after the owner_signature check succeeds:
let kid_doc = auth_manifest.kid_doc.as_ref().ok_or(KineticStoreError::InvalidManifestSignature)?;
kid_doc.verify().map_err(|_| KineticStoreError::InvalidManifestSignature)?;
auth_manifest.manifest.verify(kid_doc).map_err(|_| KineticStoreError::InvalidManifestSignature)?;
```

### [MEDIUM] No manifest version-rollback / `valid_from` enforcement on ingestion
- **[LOCATION]** `kinetic-kid/src/manifest.rs:58-94` (`verify` ignores `version` and `valid_from`) and the manifest store path
- **[VULNERABILITY]** `CapabilityManifest::verify` validates only the signature. `version` (documented as "resolvers prefer higher versions") and `valid_from` are never checked. If the store does not reject `version <= current`, an attacker who captures an older validly-signed manifest can replay it to roll services back (e.g. revert an endpoint to a since-revoked/compromised host).
- **[REMEDIATION]** Enforce strict monotonicity and freshness at ingestion: reject a manifest whose `version` is `<=` the currently stored version for that DID, and reject `valid_from > now + skew`.

### [LOW] `revocation_keys` are declared but never enforced in `verify()`
- **[LOCATION]** `kinetic-kid/src/document.rs:50-52, 71-120`
- **[VULNERABILITY]** The document carries `revocation_keys`, but `verify()` performs no revocation check; there is no revocation-list consultation. A compromised controller key remains valid until the whole document/name is replaced.
- **[REMEDIATION]** Define and enforce a revocation record type (signed by a `revocation_key`) at resolution time, or document clearly that revocation is out-of-scope for v1.

---

## kinetic-core::governance

### [HIGH] Corrupted governance state silently **resets to Founder mode** (fail-open)
- **[LOCATION]** `kinetic-core/src/governance/state_io.rs:32-47`
- **[VULNERABILITY]** The doc-comment says *"Panics if the state file exists but is corrupted"*, but the code instead renames the file to `.corrupt` and returns `GovernanceState::new(now)` — i.e. **Founder phase, empty council, fresh genesis timestamp**. Any corruption (disk bit-rot, partial write, or an attacker with write access to the state path) silently rolls governance back to founder privileges.
- **[EXPLOIT SCENARIO]** An attacker who can corrupt/truncate the governance state file (local FS access, or a crash mid-write since `save_to_disk` is atomic but readers aren't guarded against externally-truncated files) forces the node back into Founder mode on next start, re-enabling founder-only actions (`founder_premium_grants`, council bootstrap) and discarding the vetoes/timelocks/council that had accrued.
- **[REMEDIATION]** Fail **closed**: refuse to start (or load a signed checkpoint) on corruption rather than minting a fresh Founder state; and fix the comment to match behavior.
```rust
Err(e) => {
    tracing::error!("CRITICAL: Governance state corrupted: {e}. Refusing to start with a reset state.");
    let corrupt_path = path.with_extension("corrupt");
    let _ = std::fs::rename(path, &corrupt_path);
    // Do NOT silently return Founder state. Require operator intervention / signed snapshot.
    panic!("Governance state at {} is corrupt; manual recovery required (backup at {}).",
           path.display(), corrupt_path.display());
}
```

### [MEDIUM] Single-signature admission gate can mutate shared proposal state
- **[LOCATION]** `kinetic-core/src/governance/logic.rs:214-247`
- **[VULNERABILITY]** `process_governance_message` sets `is_authorized` on the **first** signature that matches root **or** guard **or** *any* active council member, then calls `merge_signatures` (which mutates the persistent `partial_proposals` map) before the real quorum check in `verify_action`. So one council member (or a leaked council key) can inject/accumulate signatures into shared state. The final execution quorum is enforced by the engine, but the pre-quorum state mutation is reachable with a single key.
- **[EXPLOIT SCENARIO]** A single malicious/compromised council key spams distinct valid proposals, growing `partial_proposals`/`pending_*` maps (pruned only by `MAX_AGE_SECONDS`), and can pre-seed signature sets for actions it favors. Bounded by requiring a valid council key, but it is more privilege than "admission" should grant.
- **[REMEDIATION]** Separate authentication (valid signer) from authorization (quorum) cleanly: only merge signatures for a proposal after validating each signature independently and cap `partial_proposals` per-signer; verify the full quorum in `verify_action` (already done) and ensure no side-effshowing state is written for unauthorized/insufficient proposals.

### [LOW] `process_governance_message` panics on `SystemTime` error; inconsistent with `state_io`
- **[LOCATION]** `kinetic-core/src/governance/logic.rs:202-205` (`.unwrap()`) vs `state_io.rs:8-11` (`unwrap_or_default`)
- **[REMEDIATION]** Use `unwrap_or_default()`/`?` consistently; never `unwrap()` on wall-clock in a network-reachable code path.

### [POSITIVE] Governance persistence is atomic
- `save_to_disk` uses `NamedTempFile` + `persist` (atomic rename) — correct (`state_io.rs:21-27`). Static root/guard keys validated for length and `REPLACE_ME` placeholders before use (`logic.rs:14-27, 108-140`).

---

## kinetic-wasm

### [HIGH] Browser light-client trusts DHT resolution with no VDF and a stubbed drand clock
- **[LOCATION]** `kinetic-wasm/src/lib.rs:59-74` (config) and `:113-136` (`resolve_domain`)
- **[VULNERABILITY]** The wasm node runs `NetworkMode::LightClient` with `initial_drand_pulse: 0` and a **fake** drand channel (`watch::channel(0)`, never updated — `:60`). `resolve_domain` fetches via `resolve_redundant_payload` and deserializes the `Reveal` with **no signature/VDF check in wasm**. On wasm32 the VDF engine returns `UnsupportedPlatform`, so resolution falls back to the "3 identical payloads" quorum (main-report finding #6). Net effect: **browser clients have no independent cryptographic verification** of resolved records and rely entirely on a Sybil-inflatable quorum, with a drand clock frozen at 0 (so any time-based consensus check is meaningless on wasm).
- **[EXPLOIT SCENARIO]** Three colluding Sybil peers (cheap — 8-bit PoW, finding #5) return identical forged Reveals; the browser resolves `example.kin` to attacker-controlled A/AAAA/PeerId records and proxies user traffic accordingly. This is the highest-impact instantiation of findings #5/#6 because it hits end-user browsers directly.
- **[REMEDIATION]** Ship a WASM-capable VDF verifier (pure-Rust class-group `verify_n_wesolowski`, or compile chiavdf verify to wasm) and require Ed25519 signature + commitment-linkage verification on the wasm resolution path; feed a **real** drand pulse over the network before honoring time-gated records; never accept records on payload-count alone. If VDF truly cannot run in-browser, require the light client to fetch from ≥N *distinct PoW-qualified* peers and verify all non-VDF invariants, and surface an "unverified" state to the caller rather than returning data as authoritative.

### [LOW] `.unwrap()` on `NonZeroUsize` and no body cap surfaced to JS
- **[LOCATION]** `kinetic-wasm/src/lib.rs:71` (`NonZeroUsize::new(10_000).unwrap()`)
- The unwrap is a constant so it's safe, but prefer `NonZeroUsize::new(...).expect(...)` with a clear message, or a `const`. Proxy body size is capped server-side (5 MB) but `fetch_proxy` returns the full body to JS with no client-side guard — fine given the server cap, worth a comment.

### [POSITIVE] `console_error_panic_hook::set_once()` is installed (`:32`) so panics surface in the browser console instead of aborting silently.

---

## Updated priority list (both reports)

| Sev | Finding | Location |
|-----|---------|----------|
| CRITICAL | #1 Sync VDF verify on swarm loop | `event_loop/swarm_handler.rs:226` |
| CRITICAL | #2 Argon2 PoW on async task | `event_loop/swarm_handler.rs:136` |
| HIGH | #3 Drand randomness unbound to signature | `kinetic-core/src/drand.rs:72` |
| HIGH | #4 Drand endpoint injection via plaintext DNS TXT | `kinetic-core/src/drand.rs:148` |
| HIGH | #5 8-bit Sybil PoW | `kinetic-network/src/pow.rs:8` |
| HIGH | #6 Light-client 3-payload VDF bypass | `event_loop/utils.rs:311` |
| HIGH | #7 World-readable infra private keys | `kinetic-node/src/identity.rs:22`, `kinetic-host/src/identity.rs:14` |
| HIGH | #8 DNS serves records with no crypto verification | `kinetic-dns/src/kinetic_records.rs:83` |
| HIGH | #9 Governance corruption → silent Founder reset | `kinetic-core/src/governance/state_io.rs:32` |
| HIGH | #10 Wasm browser client trusts unverified DHT (drand frozen at 0) | `kinetic-wasm/src/lib.rs:59,113` |
| MEDIUM | #11 SSRF filter drift (CGNAT/NAT64/0.0.0.0/8) | `kinetic-dns/src/kinetic_records.rs:166` |
| MEDIUM | #12 AuthorizedManifest skips manifest sig/DID binding | `store/verification.rs:379` |
| MEDIUM | #13 No manifest version-rollback protection | `kinetic-kid/src/manifest.rs:58` |
| MEDIUM | #14 Single-sig governance admission mutates shared state | `governance/logic.rs:214` |
| + | Main-report MEDIUM/LOW/OPT items (ban-wipe, CA TOCTOU, unbounded maps, type-dispatch, clones, etc.) | see main report |

Remaining not-yet-deep-audited: `kinetic-cli`, `kinetic-forge`, `kinetic-sim`, `kinetic-test`, `kinetic-storage` internals, and the individual governance engine strategy files (`engine/{anarchy,bicameral,council,monarchy}.rs`, where the real quorum math lives). I can continue there or start a PR implementing the CRITICAL/HIGH fixes.
