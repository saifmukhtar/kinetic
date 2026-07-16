# Getting Started

> **Two paths. Pick yours.**
>
> - **[Deploying your own network?](#path-a-deploy-your-own-network)** → You want `kinetic-forge`.
> - **[Using the `.kin` public network?](#path-b-use-the-kin-network)** → You want `kinetic-daemon`.

---

## System Prerequisites

Both paths require the same toolchain.

### Required

1. **Rust toolchain** — install via [rustup](https://rustup.rs/)
2. **C++ compiler** — required by the `chiavdf` FFI bindings (`g++` or `clang`)
3. **GMP library** — the Chia VDF engine uses GNU Multiple Precision Arithmetic for large integer math

**Ubuntu / Debian:**
```bash
sudo apt update && sudo apt install build-essential cmake libgmp-dev
```

**macOS (Homebrew):**
```bash
brew install cmake gmp
```

### Clone and Build

```bash
git clone https://github.com/saifmukhtar/kinetic.git
cd kinetic
cargo build --release
```

> ⚠️ Always build in `--release` mode. The VDF computation is highly sensitive to compiler optimizations — debug mode makes name registrations unbearably slow.

---

## Path A: Deploy Your Own Network

> *For universities, companies, governments, and communities who want a sovereign namespace under their own TLD.*

### Step 1: Run `kinetic-forge`

`kinetic-forge` is the interactive wizard that generates your `network.json` — the single file that defines your entire network identity.

```bash
./target/release/kinetic-forge
```

It will ask you for:
- Your TLD (e.g. `uni`, `acme`, `internal`)
- Your organization's base domain
- VDF difficulty (it will benchmark your hardware automatically)
- Name recycling period (how long idle names survive)
- Whether to enable Phase 2 governance auto-lock

When it finishes, you will have:
- A fully configured `network.json`
- A generated governance keypair in `./keys/` — **keep these offline**

### Step 2: Recompile with Your Network Config

```bash
cargo build --release --workspace
```

All binaries now have your network's constants compiled in. Every node your users run will share identical cryptographic constants — there is no runtime config drift possible.

### Step 3: Launch Your Bootstrap Nodes

Run `kinetic-node` on at least two stable servers. These are the DHT entry points for everyone on your network:

```bash
# On your server:
sudo ./target/release/kinetic-node

# Get the peer ID to put in network.json:
kinetic peer-id
```

Update `bootstrap_nodes` in your `network.json` with these addresses, recompile, and distribute the binaries to your users.

### Step 4: Distribute

Users on your network install `kinetic-daemon` and `kinetic-cli` built from your `network.json`. They run the daemon, register names under your TLD, and resolve them natively in their browser — same workflow as the `.kin` network, but entirely under your control.

→ **Full details:** [Fork Your Own Network](./forking.md)

---

## Path B: Use the `.kin` Network

> *For developers and builders using the canonical public network — no operator, no fees, no permission required.*

### Step 1: Launch the Daemon

The `kinetic-daemon` runs continuously in the background. It handles:
- Your local Kademlia DHT peer connection to the `.kin` network
- Split-DNS on port `53` — intercepts `.kin` queries, passes everything else through
- Local REST API on `127.0.0.1:16001`

Because binding port `53` is a privileged operation on Linux and macOS, run with `sudo`:

```bash
sudo ./target/release/kinetic-daemon
```

Once running, the daemon logs will confirm it has connected to the bootstrap DHT swarm and initialized the local Sled database.

---

### Step 2: Register Your Name (Two-Phase Protocol)

Kinetic uses a **Commit → Grind → Reveal** protocol to prevent front-running. No one can snipe your name during the VDF computation because the commitment is blind.

#### Phase 1: Commit & Grind

```bash
kinetic register example.kin
```

What happens:
1. The CLI fetches the latest `drand` Quicknet pulse (the randomness beacon)
2. Hashes your name + random salt + drand pulse + your Ed25519 public key into a blind commitment and broadcasts it to the DHT instantly
3. Starts the VDF computation — your CPU will run at full load. Time depends on name length:

| Name length | Approximate time |
|---|---|
| 8+ characters | ~2 hours |
| 6 characters | ~12 hours |
| 5 characters | ~1 day |
| 4 characters | ~15 days |

4. When done, saves your proof to `~/.config/kinetic/zones/example.kin.reveal.json`

#### Phase 2: Configure & Publish

Open `~/.config/kinetic/zones/example.kin.json` and add your DNS records:

```json
{
  "name": "example.kin.",
  "records": [
    { "type": "A", "value": "YOUR_SERVER_IP" }
  ],
  "target_kid": "did:kin:kid1abc9f7..."
}
```

Then publish to the global network:

```bash
kinetic publish example.kin
```

Your name is live globally. Any device running the Kinetic daemon can now resolve `example.kin`.

---

### Step 3: Test Resolution

**Via `dig`:**
```bash
dig @127.0.0.1 example.kin A
```
You should get an instant response with your `A` record.

**Via browser:**
Open `http://example.kin` directly in Chrome or Firefox. The daemon intercepts the DNS query transparently — no browser extension needed.

**Verify legacy traffic still works:**
```bash
dig @127.0.0.1 github.com A
```
The daemon recognizes `github.com` does not end in `.kin` and forwards it to `1.1.1.1` untouched. Normal internet is unaffected.

---

### Step 4: Keep Your Name Alive (Heartbeat)

Ownership is maintained by a continuous cryptographic heartbeat — a signature broadcast to the DHT proving your node is online. The daemon handles this automatically while it runs.

If your daemon goes offline for an extended period, the name enters **Grace-Period Escalation** — attackers must compute an exponentially harder VDF to challenge it, and you can reclaim it instantly by bringing your daemon back online during the challenge window.

→ **Full details:** [VDF Delegation, Heartbeats & Lease System](./hybrid_lease_system.md)

---

## The Kinetic UI Dashboard

Both paths include the embedded **Kinetic UI** — a React dashboard served directly from the daemon binary via `rust-embed`.

With the daemon running, open:
**[http://localhost:16001](http://localhost:16001)**

From here you can:
- Monitor DHT peer discovery in real time
- Track active VDF computation progress
- View and manage registered domains
- Inspect heartbeat status for all owned names

---

## What You Just Did

You registered a name without:
- A credit card
- A username or account
- Permission from a corporation or government
- Paying anyone, ever

Your ownership is secured entirely by cryptographic proofs stored across a global decentralized hash table. No ISP can censor your name. No registry can revoke it. No speculator can outbid you.

Welcome to Kinetic.
