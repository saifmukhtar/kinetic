# Security Policy
 
Kinetic is a decentralized naming and identity engine. Because forks of Kinetic
may secure real communities' names and identities, we take security reports
seriously and welcome scrutiny from cryptographers, security researchers, and
developers of all backgrounds.
 
## Supported versions
 
Kinetic is pre-1.0 and evolving. Security fixes are applied to the `main` branch
and the latest tagged release. Older tags are not maintained. Pin a specific
release for production and watch this repository for advisories.
 
| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ |
| Latest release tag | ✅ |
| Older tags | ❌ |
 
## Reporting a vulnerability
 
**Please do not open a public issue for security vulnerabilities.**
 
Report privately via one of:
 
- **GitHub Private Vulnerability Reporting** — the "Report a vulnerability"
  button under this repository's **Security** tab (preferred; no infrastructure
  needed on our side).
- **Email** — `saifmukhtar20@gmail.com` (replace before publishing).
  If you want to encrypt, include your PGP key and we will reply in kind.
 
Please include, as far as you can:
 
- Affected component/crate and file/line (e.g. `kinetic-network/src/...`).
- Version / commit hash.
- A description of the issue and its impact.
- Steps to reproduce or a proof-of-concept (a failing test or fuzz input is ideal).
- The **deployment tier** it applies to (public `.kin` / community fork /
  personal) — see [`THREAT_MODEL.md`](./THREAT_MODEL.md). Some issues only matter
  on the adversarial public network.
 
## What to expect
 
This is currently a solo / small-team open-source project, so timelines are
best-effort, not contractual:
 
- **Acknowledgement:** within 5 days.
- **Initial assessment / severity:** within 14 days.
- **Fix or mitigation plan:** communicated once triaged; critical issues
  prioritized immediately.
- **Coordinated disclosure:** we will agree on a disclosure date with you. We aim
  for a fix (or documented mitigation) before public disclosure, and default to a
  90-day window if we cannot fix sooner.
- **Credit:** we will credit you in the advisory and release notes unless you
  prefer to remain anonymous.
 
## Scope

**In scope:** the Rust workspace crates (`kinetic-core/`, `kinetic-types/`, `kinetic-verify/`,
`kinetic-network/`, `kinetic-daemon/`, `kinetic-vdf/`, `kinetic-vdfrs/`, `kinetic-tlock/`,
`kinetic-dns/`, `kinetic-pac/`, `kinetic-kid/`, `kinetic-storage/`, `kinetic-cli/`,
`kinetic-host/`, `kinetic-node/`, `kinetic-wasm/`, `kinetic-forge/`, `kinetic-test/`),
the external OS/keygen helper (`kinetic-OS/kinetic-keygen`), the SDKs (`kinetic-sdk`),
the Android browser (`kinetic-android`), and the Tauri desktop client (`kinetic-desktop/`).

Representative concerns: DHT record poisoning, Sybil/eclipse, reactor-starvation
DoS, signature/verification bypass, drand randomness binding, governance root key verification /
emergency halt correctness, SSRF / DNS-rebinding / path traversal in the DNS
and proxy, local key/token file permissions, and the light-client trust model.
 
**Out of scope:** issues requiring an already-compromised local OS/root; attacks
that assume breaking Ed25519 / SHA-256 / BLS / the VDF; loss of a user's own seed
phrase; third-party infrastructure an operator *chose* to configure (custom
drand, custom bootstrap); and forks that intentionally disable security features
(e.g. running with a trivial cost function on a trusted network — that is a
documented, deliberate tradeoff).
 
## Safe harbor
 
We will not pursue or support legal action against researchers who:
 
- Make a good-faith effort to avoid privacy violations, data destruction, and
  service disruption.
- Only interact with their own nodes / test networks, or the public reference
  network in a way that does not harm other users.
- Give us reasonable time to remediate before public disclosure.
 
## Hardening & verification we already run
 
Contributions are gated by an automated hygiene layer: `cargo fmt`,
`cargo clippy`, `cargo test` (unit + integration + property tests via
`proptest`), `cargo fuzz` targets, and `cargo audit`. Please keep new code
covered by tests and, where it parses untrusted input, by a fuzz target.
