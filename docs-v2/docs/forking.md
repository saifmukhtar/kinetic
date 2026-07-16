# Deploy Your Own Network with `kinetic-forge`

> *Kinetic is not a single product. It is an engine. This chapter is for anyone who wants to run their own sovereign namespace — a university, a company, a government, a community, or a developer who wants a private sandbox.*

---

## The Core Idea

Every single aspect of a Kinetic network that makes it distinct — the TLD, the VDF difficulty, the bootstrap nodes, the genesis round, the governance keys — lives in a single file: **`network.json`**.

Fork operators do not patch source code. They configure `network.json`, and `kinetic-forge` compiles the entire binary suite from it. All nodes on the network share identical compiled constants, enforced at build time via `kinetic-core/build.rs`. There is no runtime configuration drift possible.

```
network.json  →  build.rs  →  compiled constants in every binary
                                ↓
                      kinetic-node  kinetic-daemon  kinetic-host  kinetic-cli
```

---

## What You Can Configure

### Network Identity (in `network.json`)

| Field | Example | What It Controls |
|---|---|---|
| `tld` | `"uni"` | The raw TLD without the dot |
| `tld_suffix` | `".uni"` | The full suffix appended to all names |
| `did_prefix` | `"did:uni:"` | Namespaces all KID identity documents to your network |
| `network_id` | `"university-net"` | P2P network discriminator — prevents cross-network gossip |
| `base_domain` | `"yourorg.example.com"` | Your public documentation/download domain |

### Consensus Parameters

| Field | Default (`.kin`) | What It Controls |
|---|---|---|
| `benchmark_base_iterations` | `238,819,830` | VDF iterations at 1× difficulty. Set this by running `kinetic-vdf benchmark` on your target hardware and using the 30-minute calibrated value. |
| `steal_target_rounds` | `7,884,000` | Rounds until steal difficulty decays to baseline. Reduce for faster name recycling on short-lived fork networks. |
| `drand_genesis_time` | `1692803367` | Unix timestamp of the drand beacon genesis. Do not change unless using a private beacon. |
| `drand_period` | `3` | Seconds per drand pulse. Only change if running a private drand network. |
| `kinetic_genesis_drand_round` | `0` | The absolute drand round at which your network officially launched. |

> ⚠️ **Warning:** Lowering `benchmark_base_iterations` significantly makes squatting cheaper on your network. For an internal corporate fork with a trusted user base this may be acceptable. For a public-facing fork, keep this at or above the `.kin` mainnet value.

### Bootstrap Nodes

```json
"bootstrap_nodes": [
  "/ip4/YOUR_IP/tcp/6070/p2p/YOUR_PEER_ID",
  "/ip4/YOUR_IP_2/tcp/6070/p2p/YOUR_PEER_ID_2"
]
```

Run `kinetic-node` on at least two stable servers. Use `kinetic-cli peer-id` to get the peer ID after first boot. These nodes are the DHT entry points for everyone joining your network.

---

## Swappable Engines (The Plugin Architecture)

This is where Kinetic diverges from most blockchain projects. The protocol core defines **abstract traits** in `kinetic-core/src/traits.rs`. All concrete implementations are **swappable at compile time**. You are not locked into any specific backend.

### `VdfEngine` — The Computation Backend

**Trait contract** (`kinetic-core/src/traits.rs`):
```rust
pub trait VdfEngine: Send + Sync {
    fn evaluate(&self, challenge: &Commitment, iterations: u64) -> Result<VdfProof, VdfError>;
    fn verify(&self, challenge: &Commitment, proof: &VdfProof, iterations: u64) -> Result<bool, VdfError>;
}
```

**Default implementation:** `ChiaVdfEngine` in `kinetic-vdf` — wraps the Chia Network's C++ chiavdf library, using Class Groups of Imaginary Quadratic Fields with Wesolowski proofs. This requires no trusted setup.

**When you'd swap it:**
- You want to use an **RSA-based VDF** (faster proof generation, but requires a trusted setup ceremony)
- You want a **simpler hash-chain VDF** for a low-security internal network where pure Sybil resistance matters less than speed
- You are deploying on **Android or WASM** — the chiavdf C++ engine is not supported there; the trait lets you plug in a pure-Rust fallback
- You are running a **research fork** that needs a different mathematical construction for academic study

**How to swap:** Implement `VdfEngine` for your struct, pass `Arc<dyn VdfEngine>` wherever the daemon wires up the engine. The entire rest of the codebase is agnostic to the implementation.

---

### `StorageEngine` — The Database Backend

**Trait contract** (`kinetic-core/src/traits.rs`):
```rust
pub trait StorageEngine: Send + Sync {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;
    fn get(&self, key: &[u8]) -> Result<Option<bytes::Bytes>, StorageError>;
    fn delete(&self, key: &[u8]) -> Result<(), StorageError>;
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError>;
}
```

**Default implementations:**
- **Native (Linux/macOS/Windows):** `SledStorage` in `kinetic-storage` — backed by `sled`, a pure-Rust embedded B-tree database. Zero external dependencies, ACID transactions, crash-safe.
- **WASM (browser):** Automatic fallback to an in-memory `BTreeMap` behind an `RwLock`. Same trait, zero interface changes.

**When you'd swap it:**
- You want **RocksDB** for higher write throughput on a heavily loaded infrastructure node
- You want **SQLite** for a more familiar embedded database with richer query support
- You want a **distributed store** (e.g., etcd or TiKV) for a clustered multi-node deployment where multiple `kinetic-node` instances share state
- You are deploying to a **read-only filesystem** and need a pure in-memory implementation for testing
- Your fork runs in a **constrained embedded environment** (Raspberry Pi, IoT) with limited disk I/O

**How to swap:** Implement `StorageEngine` for your struct and pass `Arc<dyn StorageEngine>` at construction time. The entire daemon, DHT layer, and networking stack accept the trait object — they are completely unaware of the underlying backend.

---

## Deploying with `kinetic-forge`

`kinetic-forge` is the interactive wizard that generates your `network.json` and validates it before compilation.

```bash
cargo run --bin kinetic-forge
```

It will walk you through:

```
? What is your network TLD? (e.g. uni, acme, internal)
> uni

? What is your organization's base domain?
> youruni.edu

? Benchmark your hardware first? [Y/n]
> Y
  Running VDF benchmark... (this takes ~2 minutes)
  Detected: 7,960,661 iterations/min on this machine
  Suggested benchmark_base_iterations for 30-min baseline: 238,819,830

? Accept suggested value? [Y/n]
> Y

? How long should idle names survive before becoming reclaimable?
  (in months, default: 9)
> 6

Generating governance keypair...
  Root Key:  saved to ./keys/root.key (KEEP THIS OFFLINE)
  Guard Key: saved to ./keys/guard.key (KEEP THIS OFFLINE)

Writing network.json...
Done. Build your network with: cargo build --release --workspace
```

---

## The Fork Squatter Problem (Why You Don't Need to Worry)

On a fork, squatters face a fundamentally broken incentive model:

1. They burn hours of CPU registering premium names on your `.uni` network
2. The names have zero external value — nobody outside your network sees them
3. If the problem becomes severe, you restart the network with a clean state
4. Their computational investment is completely wiped. Zero rent extracted.

This asymmetry means rational squatters will not bother with forks. They can only profit on the canonical `.kin` network — and there, the VDF difficulty cliff stops them at the protocol level.

**Your fork's ultimate security guarantee is operator sovereignty.** No squatter can outrun a restart.

---

## Example Fork Deployments

| Fork Type | Suggested Config |
|---|---|
| University internal namespace | Lower `benchmark_base_iterations` by 50%, reduce `steal_target_rounds` to 3 months, enable Phase 2 auto-lock |
| Corporate service discovery | Use default difficulty, disable Phase 2 (operator retains permanent control), private bootstrap nodes only |
| Government public services | Full default difficulty, strict 69% council governance, public bootstrap nodes |
| Developer sandbox | Dev mode (`is_dev_mode() = true`), 1000-iteration VDF, temp storage backend |
| Research / academic fork | Swap `VdfEngine` to a custom construction, keep default storage |

---

## What Stays the Same Across All Forks

No matter what you configure, every Kinetic fork inherits:
- The **four-layer KID identity architecture** (name → KID → Capability Manifest → services)
- The **Split-DNS loopback interception** (your TLD is intercepted, everything else passes through)
- The **Redundant Deterministic Storage** Eclipse attack defense
- The **Competitive Gossip** VDF validation at the network edge
- The **Epoch-Bound transport identity** DoS defense on `kinetic-host`
- The **Bicameral governance** OTA update pipeline

The engine is the same. The network is yours.
