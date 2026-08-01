# Kinetic Protocol — Threat Model
 
> Status: living document. This describes what Kinetic defends against, what it
> assumes to be trusted, and where the security boundaries are. It is written per
> **deployment tier**, because Kinetic is an *engine*: the public `.kin` network
> and a private university/community fork have very different threat models.
 
---
 
## 1. What Kinetic is (in one paragraph)
 
Kinetic is a decentralized naming and identity engine. Instead of paying a
registrar (ICANN model) or a token/gas fee (blockchain model), a registrant
proves **computational effort** via a Verifiable Delay Function (VDF), bound to a
public randomness beacon (drand). Names, identity documents (KIDs), and capability
manifests live in a libp2p Kademlia DHT and are resolved through a local daemon
that also serves split-DNS and an HTTP proxy for `.kin` traffic. The cost
function, governance model, and TLD are **compile-time configurable** (see
`network.json` + `kinetic-core/build.rs`), so forks can trade security for simplicity.
 
---
 
## 2. Deployment tiers (read this first)
 
Security expectations differ dramatically by tier. State which tier you are in
before reasoning about any threat.
 
| Tier | Example | Membership | Cost function | Sybil resistance needed? | Governing control |
|------|---------|------------|---------------|--------------------------|-------------------|
| **T0 — Public `.kin`** | The official reference network | Open / anonymous / adversarial | Full VDF + PoW | **Yes — critical** | Root key (Sovereign) |
| **T1 — Community / campus fork** | `.uni` on a campus network | Known, semi-trusted | Hashcash or light VDF | Low — social reset covers it | Single operator (Sovereign) |
| **T2 — Personal / experimental** | A developer's laptop / lab | Single operator | Trivial / disabled | No | Operator is root |
 
**Key consequence:** most of the heavyweight defenses (16 MiB Argon2id PoW `Source: kinetic-network/src/pow.rs:62`,
long VDFs, quorum math) exist for **T0**. In **T1/T2** the intended defense is
*social* — a trusted group can press a "reset" and re-register their known names,
making squatting economically pointless. In those tiers, the security-critical
primitive is **the reset/governance path**, not Sybil resistance.
 
---
 
## 3. Assets we protect
 
1. **Name ownership** — the binding `apex.kin → owner keypair`, and the
   right to renew/update it.
2. **Identity integrity (KID)** — a `did:kin:<sha256(pubkey)>` must only be
   controllable by the holder of the matching private key.
3. **Resolution integrity** — a resolver must not return a record the legitimate
   owner did not publish (no DHT poisoning / cache poisoning).
4. **Node availability** — a single peer must not be able to freeze or exhaust
   another node cheaply.
5. **Local key material** — Ed25519 identity keys and the API token must not be
   readable by other local users or leaked in logs.
6. **User-owned data (KID app model)** — data anchored to a KID (posts, likes,
   app state) stays under the user's control and is portable across apps.
 
---
 
## 4. Adversary model
 
We assume a **sophisticated, active adversary** on T0 with the ability to:
 
- Run many nodes cheaply (Sybil) and choose their PeerIds.
- Send arbitrary, malformed, or maximal-size DHT records and P2P messages.
- Flood connections / queries (DoS).
- Position themselves on the network path for plaintext traffic (MITM), including
  DNS responses and any non-TLS beacon/seed traffic.
- Attempt to become a victim's only peers (eclipse).
- Corrupt or truncate on-disk state if they gain local write access.
- Craft hostile inputs to the DNS resolver and HTTP proxy (SSRF, DNS-rebinding,
  path traversal).
 
We assume the adversary **cannot**:
 
- Break Ed25519, SHA-256, BLS (drand), or the VDF's sequentiality assumption.
- Read memory of a process they do not control, or defeat OS file permissions
  set correctly.
- Forge a drand beacon signature under the pinned public key.
 
---
 
## 5. Trust assumptions (be honest about these)
 
- **The VDF sequentiality assumption holds** — proofs cannot be produced
  meaningfully faster than the target time, and discriminants are well-formed.
- **The drand beacon (pinned public key) is honest and available** for T0. Its
  randomness seeds VDF challenges; if an attacker controls the *delivered*
  randomness (e.g. via a MITM'd/plaintext endpoint) they influence challenges.
  → Randomness MUST be cryptographically bound to the beacon signature and only
  fetched over authenticated channels.
- **Bootstrap nodes / seed domains are reachable and not fully compromised.**
  These are a known centralization point (see §7).
- **The root governance key is generated offline and kept air-gapped.**
  The `kinetic-core/src/constants.rs` file must replace the
  `REPLACE_ME_*` placeholders in `ROOT_PUBLIC_KEY_HEX` before any real T0 deployment.
- **The local machine is not already compromised.** Kinetic protects key files
  with `0o600`, but cannot defend against a local attacker who is already root.
- **In T1/T2, the human members controlling reset/governance are honest.**
 
---
 
## 6. In scope vs. out of scope
 
**In scope:** DHT record poisoning/overwrite; Sybil/eclipse; reactor starvation
via CPU/memory-heavy work on the async executor; unbounded resource growth;
signature/verification bypasses; drand randomness binding; governance quorum,
timelock, and reset correctness; SSRF/DNS-rebinding/path-traversal in the DNS +
proxy; local key/token permissions; light-client (wasm/mobile) trust model.
 
**Out of scope (documented, not defended):** a compromised local OS/root; a
global adversary who defeats the underlying crypto; loss of the user's own seed
phrase; availability of third-party infrastructure the operator chooses (custom
drand, custom bootstrap); theft of the offline Root key; correctness of
forks that disable security features intentionally.
 
---
 
## 7. Known centralization points (and mitigations)
 
Kinetic is decentralized in operation but has bootstrapping dependencies. Naming
them explicitly is part of the threat model:
 
1. **Hardcoded bootstrap nodes** (`network.json → bootstrap_nodes`) and **seed
   domains** — a network-level or nation-state adversary could seize/block these.
   *Mitigation:* ship multiple diverse bootstrap addresses; allow operator-supplied
   bootstrap; support mDNS/local discovery for LAN forks; consider a signed,
   gossip-distributed peer list so bootstrap is a hint, not an authority.
2. **drand beacon endpoints** — plaintext or single-provider fetch is a MITM/seizure
   risk. *Mitigation:* pin the beacon public key, require HTTPS, verify the
   signature *and* that `randomness == H(signature)`, and query multiple providers.
3. **`docs_url` / error pages** — informational only; must never be trusted for
   security decisions.
 
---
 
## 8. Component-level threats (map to the audit)
 
| Component | Primary threats | Notes |
|-----------|-----------------|-------|
| `kinetic-network` (swarm/DHT) | Reactor starvation (sync VDF/PoW on the event loop), Sybil, eclipse, record poisoning, unbounded maps | Highest-risk crate on T0. Offload CPU/crypto to `spawn_blocking` with bounded concurrency. Enforces 16 MiB Argon2id PoW `(Source: kinetic-network/src/pow.rs:62)`. |
| `kinetic-core` (drand, governance, names) | Randomness binding, quorum math, timelock bypass, fail-open on corrupt state, name-validation as path sanitizer | Governance/reset path is the T1/T2 crown jewel. Enforces Sovereign Root key rules `(Source: kinetic-core/src/governance/engine/sovereign.rs)`. |
| `kinetic-vdf` (Chia FFI) | `unsafe` FFI invariants, discriminant integrity, timing | Verify all invariants before raw pointer use. Discriminant derivation must match exactly between evaluate and verify. |
| `kinetic-daemon` (DNS/proxy/CA/API) | SSRF, DNS-rebinding, path traversal, local-CA name-constraints, host-header validation, API auth/permissions | Local CA must be name-constrained so it can never MITM non-`.kin` traffic. |
| `kinetic-dns` | Serving unverified records, cache poisoning, SSRF filter drift | DNS layer should not be the trust boundary; verify upstream of the cache. Enforces max 50 records per zone `(Source: kinetic-core/src/types/dns.rs:135)`. |
| `kinetic-kid` | DID hijack, manifest rollback, revocation enforcement | DID↔pubkey binding is strong; manifest version/`valid_from` and revocation (via explicit revocation keys) need enforcement. Max 20 keys. |
| `kinetic-wasm` / mobile light client | Accepting records without VDF verification, frozen drand clock | Light clients must not accept "N identical payloads" as proof. |
| `kinetic-storage` | Fail-open corruption recovery, unbounded storage | Separate cache (safe to reset) from authoritative local state (fail closed). |
| `kinetic-client/desktop` (Tauri App) | IPC compromise, Webview XSS, unauthorized local key/token access | Tauri architecture places frontend webview in untrusted scope and Rust backend in trusted scope. IPC messages must be heavily sanitized `(Source: kinetic-client/desktop/src-tauri)`. |
| `kinetic-cli` / `kinetic-forge` | Key lifecycle (discarded controller keys), plaintext beacon defaults, path handling | User-facing footguns. |
 
---
 
## 9. Security goals summary (what "secure" means here)
 
- **T0:** an adversary with large but bounded compute cannot poison a name/KID a
  correct node will accept, cannot cheaply freeze a node, and cannot push a
  binary update without quorum + timelock.
- **T1/T2:** an adversary cannot press or forge the reset/governance action, cannot
  impersonate a member's key, and cannot exhaust the operator's node; squatting is
  neutralized by the community reset rather than by cryptographic cost.
 
---
 
## 10. Reporting
 
Security issues: see [`SECURITY.md`](./SECURITY.md). Please report privately
before public disclosure.
