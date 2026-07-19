# Kinetic Protocol — Security Audit Addendum 2

Covers the governance engine strategy files (`anarchy`/`bicameral`/`council`/`monarchy`), `kinetic-storage` internals, `kinetic-cli`, `kinetic-forge`, `kinetic-sim/keygen`, and `kinetic-test`. Same format; findings continue at #15. This completes the crate-by-crate pass.

---

## kinetic-core::governance (engine strategies + quorum math)

### [HIGH] `ExecuteTimelock` bypasses the timelock maturity check
- **[LOCATION]** `kinetic-core/src/governance/engine/monarchy.rs:81-89`; `bicameral.rs:300-325` (reachable via Founder-mode root path `bicameral.rs:56-96`)
- **[VULNERABILITY]** The OTA/binary-update timelock is stored as `pending_updates: HashMap<Hash256, (broadcast_time, wait_time, mirrors)>`. The **legit** maturity path `GovernanceState::check_timelocks` (`logic.rs:171-190`) correctly requires `current_time >= broadcast_time + wait_time`. But the `ExecuteTimelock` action handler removes the entry and fires the effect **without checking elapsed time**:
```rust
// monarchy.rs:81-89 (identical shape in bicameral.rs:319-324)
GovernanceAction::ExecuteTimelock { target_hash } => {
    state.pending_timelocks.remove(target_hash);
    if let Some((_, _, mirrors)) = state.pending_updates.remove(target_hash) { // (_, _) drops broadcast_time & wait_time!
        effect = Some(GovernanceEffect::TriggerOTA { manifest_hash: *target_hash, mirrors });
    }
}
```
In monarchy, `verify_action` only checks `root_signed` before dispatching, so the root key can queue an `UpdateBinary` (1–3 day wait) and immediately submit `ExecuteTimelock` to trigger the OTA **now**. In bicameral **Founder** mode, the same is reachable with the root signature.
- **[EXPLOIT SCENARIO]** The whole point of the 1–3 day OTA timelock is to give the guard key / community a veto window against a malicious binary push. A compromised (or coerced) root key defeats it: queue `UpdateBinary{malicious_manifest}`, then `ExecuteTimelock` in the same breath → every node fetches and applies the attacker's binary with zero delay. This is a supply-chain kill-switch.
- **[REMEDIATION CODE]** Enforce maturity inside `ExecuteTimelock`, and don't discard the timing tuple:
```rust
GovernanceAction::ExecuteTimelock { target_hash } => {
    if let Some((broadcast_time, wait_time, mirrors)) = state.pending_updates.get(target_hash).cloned() {
        if current_time_sec < broadcast_time.saturating_add(wait_time) {
            return; // not matured — refuse (verify_action should surface TimelockNotMatured)
        }
        if state.vetoed_hashes.contains(target_hash) { state.pending_updates.remove(target_hash); return; }
        state.pending_updates.remove(target_hash);
        state.pending_timelocks.remove(target_hash);
        effect = Some(GovernanceEffect::TriggerOTA { manifest_hash: *target_hash, mirrors });
    }
}
```
(and make `verify_action` return a real error for a premature/veto'd timelock rather than executing).

### [MEDIUM] Quorum is measured against *active* council, disenfranchising honest-but-idle members
- **[LOCATION]** `logic.rs:90-101` (`count_active_council`), `bicameral.rs:23-53`, `council.rs:23-73`
- **[VULNERABILITY]** Thresholds (69/90/95%) are computed against `council_size_at_proposal`, which the proposer must set `>= max(active_count, MIN_ACTIVE_COUNCIL)` — where `active_count` counts only members who signed *something* within `ACTIVE_WINDOW_SECONDS`. Honest members who haven't signed recently are excluded from the denominator, so a smaller clique of currently-active members can satisfy the percentage.
- **[EXPLOIT SCENARIO]** If most legitimate council members go quiet (vacation, key rotation, apathy), the "effective" council shrinks toward `MIN_ACTIVE_COUNCIL`, and a coordinated active minority can push 90–95% actions (`RemoveCouncilMember`, `GrantPremiumName`, `RotateGuardKey`) against the wishes of the (idle) majority. Attackers can also *induce* inactivity (e.g. griefing that keeps honest members from getting their signatures included) to lower the bar.
- **[REMEDIATION]** Base the denominator on the full `active_council.len()` (total appointed members), not the recently-active subset; use activity only for liveness/removal decisions, not for shrinking the quorum denominator. If liveness-weighting is intentional, require an explicit, signed "member inactive" transition before dropping someone from the denominator.

### [MEDIUM] Dead / inconsistent `EmergencyReset(override_mode)` timelock path
- **[LOCATION]** `bicameral.rs:118-146, 283-325`, `logic.rs:171-190`
- **[VULNERABILITY]** An `override_mode` `EmergencyReset` in Council mode inserts into `pending_timelocks` (`bicameral.rs:288-292`), but **nothing consumes it**: `check_timelocks` only processes `pending_updates`, and `ExecuteTimelock` hits `_ => UnhandledThresholdMath` in Council mode (`bicameral.rs:210`), so it can't run there. The override reset is therefore inert in Council mode, while the *non-override* branch applies the reset immediately (`:293-298`). This is an ambiguous, under-specified security-critical state machine: the "delayed, vetoable" reset silently never happens, and only the instant reset works.
- **[REMEDIATION]** Make the timelock path explicit and consumable: route matured `pending_timelocks` through `check_timelocks` (with maturity + veto checks) exactly like `pending_updates`, and add a test that an override reset only takes effect after the delay and can be vetoed within it.

### [LOW] Startup panics & wall-clock `unwrap`
- **[LOCATION]** `engine/mod.rs:15-18` (`panic!` on unknown `GOVERNANCE_MODEL`), `logic.rs:202-205` (`.unwrap()` on `SystemTime`)
- **[REMEDIATION]** Fail with a typed error / documented startup abort for bad config; use `unwrap_or_default()` for wall-clock as `state_io.rs` already does.

### [POSITIVE] Governance quorum counting is otherwise sound
- Signatures are deduplicated per council **index** (`counted_members`, `bicameral.rs:159-171`, `council.rs:44-54`) so one key can't be counted twice; canonical signing bytes use explicit per-variant domain-separator tags + length-prefixed fields (`types.rs:104-184`); `RotateRootKey` additionally requires a guard signature (`bicameral.rs:189-201`); anarchy correctly rejects everything.

---

## kinetic-storage

### [MEDIUM] Sled corruption silently backs up and starts fresh (fail-open, local state loss)
- **[LOCATION]** `kinetic-storage/src/lib.rs:48-66`
- **[VULNERABILITY]** On `sled::Error::Corruption`, the DB dir is renamed to `*.corrupt.bak` and a **new empty DB** is opened. For the DHT record cache that's tolerable (records refetch from the network), but the same store also holds **local, non-recoverable state** — the daemon's domain ownership reveals, zone files' companion state, heartbeat rounds, banned-peer list. A single corruption event silently wipes them with no operator signal beyond a log line. Also `let _ = std::fs::remove_dir_all(&bak_path);` (`:56`) destroys any *previous* backup before making the new one, so repeated corruption loses earlier snapshots.
- **[EXPLOIT SCENARIO]** An attacker (or power-loss during a write) who can induce/*trigger* a corruption forces loss of the node's ownership state; on restart the node no longer defends its own names' heartbeats, easing a name steal. Fail-open on security-relevant local state is the wrong default.
- **[REMEDIATION]** Separate the *cache* tree (safe to auto-reset) from *authoritative local state* (ownership/identity). For the latter, fail closed on corruption (require operator intervention / restore from the `.bak`), and never delete an existing backup — timestamp them.

### [LOW] Lock detection via substring-matching the error string
- **[LOCATION]** `kinetic-storage/src/lib.rs:37-45`
- **[VULNERABILITY]** "Is the DB already locked?" is decided by `err_str.contains("lock") || ... "would block"` — locale- and version-fragile; a non-English or reworded sled/OS error mis-classifies a lock as a generic failure (or vice versa).
- **[REMEDIATION]** Match on the structured error kind (e.g. inspect `io::ErrorKind::WouldBlock`/platform errno) rather than the human string.

### [NOTE] No size bounds at the storage layer
- `put`/`scan_prefix` impose no per-key/value or total limits; bounds live only in callers (`put_record` 80 KiB, reveal-scan caps). The unbounded heartbeat scan called out in the main report (`store/core.rs:111`) is thus fully unbounded at this layer too.

---

## kinetic-cli

### [MEDIUM] `identity create` discards the KID controller private key
- **[LOCATION]** `kinetic-cli/src/commands/identity.rs:42-84`
- **[VULNERABILITY]** `Create` generates a fresh Ed25519 keypair, derives the DID as `SHA-256(pubkey)`, signs the document, writes only the **public** `kid.json`, and drops the `SigningKey`. The controller private key is never persisted. Meanwhile `Publish` signs `AuthorizedKid`/`AuthorizedManifest` with the *node* `identity.key` (`:93, 106, 135`), a **different** key. So the DID is cryptographically bound (via the hash) to a key nobody can ever use again.
- **[EXPLOIT SCENARIO]** Not a remote exploit, but a structural identity-lifecycle break: the DID's controller can never rotate keys, revoke, re-sign the document, or issue a controller-signed manifest — the only authority that persists is the domain-owner key, and (per addendum-1 finding #12) the ingestion path doesn't verify the manifest against the KID document anyway. Combined, the entire `kinetic-kid` controller-key machinery is effectively dead in the CLI-driven flow.
- **[REMEDIATION]** Persist the controller key securely (temp file + `0o600` + rename, mirroring `kinetic-core/types/identity.rs:126-137`), or explicitly derive the KID controller key from the node identity / seed so it is recoverable, and use it (not the node key) to sign manifests. Make the intended key model explicit.

### [LOW] `save_zone_file` / `normalize_name` are not path sanitizers
- **[LOCATION]** `kinetic-cli/src/utils.rs:28-37`; `kinetic-core/src/types/names.rs:5-14`
- **[VULNERABILITY]** `save_zone_file` builds `zones_dir.join(format!("{}.json", fqdn))` and `normalize_name` only lowercases / strips trailing dots / appends the TLD — it does **not** reject `/` or `..`. Path safety depends entirely on every caller running `is_valid_apex_name` first (which *does* enforce strict LDH and would reject traversal). Today the call sites (`publish.rs:26→100`, `register.rs` post-API-success) are gated, so it's not currently exploitable — but it's a landmine: any future caller that path-joins a `normalize_name` result without validation gets traversal (`normalize_name("../../etc/x") → "../../etc/x.kin"`). Same shape as the daemon zone-write noted in the main report.
- **[REMEDIATION]** Validate inside `save_zone_file` (call `is_valid_apex_name`, reject on error) and/or take a typed `ValidatedApexName` instead of `&str`, so the type system enforces the invariant.

### [POSITIVE] CLI crypto/auth hygiene
- `seed init` uses `getrandom::fill` for 32-byte entropy and stores via `save_keypair_from_mnemonic` (`0o600`, atomic); `Restore` reads the phrase with `rpassword` (no echo); `build_client` attaches the bearer token from the `0o600` token file (`utils.rs:44-74`). Apex-name validation (`names.rs:46-95`) is strict LDH with reserved/infrastructure lists.

---

## kinetic-forge

### [LOW] Custom-drand wizard permits a plaintext-HTTP beacon; 32-bit network id
- **[LOCATION]** `kinetic-forge/src/main.rs:91-102, 53-58`
- **[VULNERABILITY]** (a) The private-network path accepts an arbitrary Drand HTTP endpoint and even suggests `http://my-drand.internal` (`:92`). A plaintext beacon is MITM-able, and — per main-report finding #3 — the randomness isn't bound to the signature, so a MITM'd `http` beacon fully controls VDF challenges on that private network. (b) `network_id` uses only the first 4 bytes of `SHA-256(network_name)` (`:57`), a 32-bit space, so two private networks can collide protocol-isolation IDs.
- **[REMEDIATION]** Require `https://` for beacon endpoints (or a pinned public key + the randomness-binding fix), and widen `network_id` to ≥16 bytes.

---

## kinetic-sim/keygen

### [LOW] Simulation keygen writes world-readable libp2p keys and panics on error
- **[LOCATION]** `kinetic-sim/keygen/src/main.rs:14-19`
- **[VULNERABILITY]** `File::create(path)` (default perms) + `write_all(private_key_protobuf)`; every step `.unwrap()`. It's simulation/containerized tooling (not a workspace member, not shipped), so impact is confined to test topologies, but it repeats the world-readable-key pattern from finding #7.
- **[REMEDIATION]** Same `0o600` write helper if these keys ever represent real identities in a shared sim host; otherwise document as sim-only.

---

## kinetic-test

- **[CLEAN]** Entirely `#[cfg(test)]` integration tests (`kinetic-test/src/lib.rs:1-2`); no production code path and no security bypass compiled into release. Notably its harness runs with `disable_pow: false` and a real VDF engine (`:24, 38-39`), so it exercises production security behavior rather than stubbing it — good. (Contrast with the `#[cfg(test)]` verification bypass flagged for `event_loop/utils.rs` in the main report, which is in a *production* crate.)

---

## Consolidated new findings (this addendum)

| Sev | # | Finding | Location |
|-----|---|---------|----------|
| HIGH | 15 | `ExecuteTimelock` skips maturity → OTA/reset timelock bypass | `governance/engine/monarchy.rs:81`, `bicameral.rs:300` |
| MEDIUM | 16 | Quorum denominator = *active* council → minority takeover | `governance/logic.rs:90`, `bicameral.rs:23`, `council.rs:23` |
| MEDIUM | 17 | Dead/ambiguous `EmergencyReset(override)` timelock path | `governance/engine/bicameral.rs:288` |
| MEDIUM | 18 | Sled corruption → silent fresh DB (local state loss, fail-open) | `kinetic-storage/src/lib.rs:48` |
| MEDIUM | 19 | `identity create` discards KID controller private key | `kinetic-cli/src/commands/identity.rs:42` |
| LOW | 20 | Governance startup panics / wall-clock unwrap | `governance/engine/mod.rs:15`, `logic.rs:202` |
| LOW | 21 | Sled lock detection via error-string matching | `kinetic-storage/src/lib.rs:37` |
| LOW | 22 | `save_zone_file`/`normalize_name` not path sanitizers | `kinetic-cli/src/utils.rs:28`, `names.rs:5` |
| LOW | 23 | Forge allows plaintext-HTTP beacon; 32-bit network id | `kinetic-forge/src/main.rs:91,57` |
| LOW | 24 | Sim keygen world-readable keys + panics (sim-only) | `kinetic-sim/keygen/src/main.rs:14` |

**Crate coverage is now complete** across the workspace (core incl. governance, vdf, network, storage, dns, daemon, kid, wasm, cli, forge, node, host, keygen, test, and the sim keygen). The full picture spans 3 documents: the main report (#1–#7 + MEDIUM/LOW/OPT), addendum 1 (#8–#14: dns/kid/governance-persistence/wasm), and this addendum 2 (#15–#24). The standout risks remain the two CRITICAL reactor-starvation bugs (#1/#2), the drand randomness binding (#3/#4), the Sybil/light-client trust chain (#5/#6/#10), and now the governance timelock bypass (#15). I can start a PR implementing the CRITICAL/HIGH fixes whenever you want.
