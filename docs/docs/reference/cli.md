# CLI Reference

The `kinetic` command is the primary interface for managing your Kinetic node, registering names, and handling your cryptographic identity. It communicates with the locally running `kinetic-daemon` via the REST API, authenticating every request using the bearer token stored in your data directory.

**Requires a running daemon for most commands.** Exceptions: `kinetic seed init`, `kinetic seed restore`, `kinetic setup`, `kinetic clock`, `kinetic dns-tree`.

::: tip Data Directory
All commands read configuration from your OS data directory:
- **Linux**: `~/.local/share/kinetic/`
- **macOS**: `~/Library/Application Support/kinetic/`
- **Windows**: `%APPDATA%\kinetic\`
:::

---

## Command Groups

| Group | Purpose |
|---|---|
| [`kinetic setup`](#setup) | Interactive first-run wizard |
| [`kinetic seed`](#seed) | Generate or restore your 24-word identity |
| [`kinetic daemon`](#daemon) | Manage the main Kinetic Daemon process |
| [`kinetic dns`](#dns) | Manage the Kinetic DNS server (requires root) |
| [`kinetic host`](#host) | Manage the Kinetic Host (website/content hosting) |
| [`kinetic node`](#node) | Manage a full DHT node |
| [`kinetic name`](#name) | Register, publish, renew, and query `.kin` names |
| [`kinetic identity`](#identity) | Create and manage Kinetic Identity Documents (KID) |
| [`kinetic governance`](#governance) | Submit and sign governance proposals |
| [`kinetic dns-tree`](#dns-tree) | Generate Merkle DNS tree zone files for bootstrap |
| [`kinetic clock`](#clock) | Display Kinetic Network Time |

---

## `kinetic setup`

Interactive first-run wizard. Generates your node identity and prints the next steps.

```bash
kinetic setup
```

What it does:
1. Generates a new 24-word seed phrase and derives your `identity.key`
2. Prompts you to verify two random words from your seed phrase
3. Prints the three commands to start your node

::: warning
`setup` is equivalent to `kinetic seed init`. Running it on an existing node will overwrite your identity.
:::

---

## `kinetic seed`

Manages your node's master seed phrase. Your seed is a 24-word BIP-39 mnemonic that is the root of your cryptographic identity. **If you lose both your seed and your `identity.key` file, you permanently lose ownership of all names you have registered.**

### `kinetic seed init`

Generates a new 24-word seed phrase and derives the node's Ed25519 identity key.

```bash
kinetic seed init
```

**What happens:**
1. Generates 32 bytes of cryptographic entropy from the OS
2. Derives a 24-word BIP-39 mnemonic from that entropy
3. Prints the full seed phrase to the terminal — **write it down immediately**
4. Prompts you to enter two randomly chosen words from the phrase to verify your backup
5. Derives the `identity.key` and saves it to your data directory

::: danger ONE-TIME DISPLAY
The seed phrase is shown **once**. It is never stored in readable form. After this screen closes, it is gone. Write it down before pressing Enter.
:::

**Example output:**
```
========================================================
🚨 NEW IDENTITY CREATED - BACKUP IMMEDIATELY 🚨
========================================================
Write down this 24-word seed phrase and store it safely:

correct horse battery staple abandon zoo pizza cloud ...

WARNING: This is a one-way derivation. You will NEVER
be able to view this phrase again.
========================================================

To verify your backup, please enter word #7: 
Please enter word #19: 
```

**Files written:**
- `identity.key` — your private node key (binary, Ed25519)

::: tip If you already ran init
Re-running `kinetic seed init` will **overwrite** your existing `identity.key`. Only do this if you intend to create a completely new identity and are prepared to lose access to any names registered under the old one.
:::

---

### `kinetic seed restore`

Restores a node identity from an existing 24-word seed phrase. Use this when migrating to a new machine or recovering from data loss.

```bash
kinetic seed restore
```

**What happens:**
1. Prompts you to enter your full 24-word seed phrase (input is hidden, like a password)
2. Derives the identity key from the phrase
3. Writes the restored `identity.key` to your data directory

**Example:**
```bash
$ kinetic seed restore
Enter your 24-word seed phrase: ████████████████████████████████
```

::: warning
After restoring, restart your daemon. Your registered names will become accessible again once the daemon reconnects to the DHT network.

**What seed restore cannot recover:** your `zones/*.reveal.json` proof files. Back those up separately — see [File Paths](/users/file-paths).
:::

---

## `kinetic daemon`

Manages the `kinetic-daemon` process — the main Kinetic service responsible for DHT participation, VDF proof handling, the local REST API, and the local DNS proxy.

All subcommands below also apply to `kinetic host`, `kinetic node`, and `kinetic dns` — they share the same lifecycle interface.

### `kinetic daemon run`

Start the daemon in the **foreground** (terminal blocks). Useful for debugging.

```bash
kinetic daemon run
```

Logs stream directly to stdout. Press `Ctrl+C` to stop.

---

### `kinetic daemon install`

Register the daemon as a **background system service** that starts automatically on boot.

```bash
kinetic daemon install
```

- **Linux**: Creates and enables a `systemd` unit
- **macOS**: Creates a `launchd` plist in `~/Library/LaunchAgents/`
- **Windows**: Registers a Windows Service

---

### `kinetic daemon uninstall`

Remove the background system service registration.

```bash
kinetic daemon uninstall
```

---

### `kinetic daemon start`

Start the already-installed background service.

```bash
kinetic daemon start
```

---

### `kinetic daemon stop`

Stop the running background service.

```bash
kinetic daemon stop
```

---

### `kinetic daemon status`

Check whether the background service is currently running.

```bash
kinetic daemon status
```

- **Linux**: Calls `systemctl is-active kinetic-daemon`
- **macOS**: Calls `launchctl list kinetic-daemon`
- **Windows**: Not yet supported

---

### `kinetic daemon logs`

Tail the live log output from the background service.

```bash
kinetic daemon logs
```

- **Linux**: Calls `journalctl -u kinetic-daemon -f`
- **macOS**: Prints the path to the log files under `/tmp/`

---

## `kinetic dns`

Manages the `kinetic-dns` server — the system-wide DNS resolver that allows `.kin` names to resolve in your browser and other system applications.

::: warning Requires Root
The DNS server binds to port 53, which requires administrator or root access. All `kinetic dns` subcommands automatically prepend `sudo` on Linux and macOS. You will be prompted for your password.
:::

All lifecycle subcommands are identical to [`kinetic daemon`](#kinetic-daemon):

```bash
kinetic dns run       # foreground (sudo)
kinetic dns install   # install as system service (sudo)
kinetic dns start     # start background service (sudo)
kinetic dns stop      # stop background service (sudo)
kinetic dns status    # check service status
kinetic dns logs      # tail service logs
kinetic dns uninstall # remove system service (sudo)
```

---

## `kinetic host`

Manages the `kinetic-host` process — for serving websites or services reachable at your `.kin` name. Designed for VPS or homelab deployments.

All lifecycle subcommands are identical to [`kinetic daemon`](#kinetic-daemon):

```bash
kinetic host run
kinetic host install
kinetic host start
kinetic host stop
kinetic host status
kinetic host logs
kinetic host uninstall
```

---

## `kinetic node`

Manages the `kinetic-node` process — a full DHT node that contributes to network health without hosting content. Run this if you want to support the Kinetic network beyond your own names.

```bash
kinetic node run
kinetic node install
kinetic node start
kinetic node stop
kinetic node status
kinetic node logs
kinetic node uninstall
```

---

## `kinetic name`

Domain name operations: register, publish, renew, list, inspect, and resolve `.kin` names.

---

### `kinetic name register`

Claim ownership of a `.kin` name by computing a VDF proof. This is the primary name registration command.

```bash
kinetic name register <name> [--iterations <n>]
```

**Arguments:**

| Argument | Required | Description |
|---|---|---|
| `<name>` | ✅ | The name to register (e.g. `myname.kin`). The `.kin` suffix is added automatically if omitted. |
| `--iterations`, `-i` | ❌ | Number of VDF iterations. Default: `4,194,304`. The daemon automatically computes the protocol-required minimum for the name length — your value is used as a floor, not an override. |

**What happens (in order):**
1. Fetches the latest drand beacon for cryptographic randomness
2. Constructs a commitment: `H(name || salt || drand_randomness || pubkey)`
3. Broadcasts the commitment to the DHT immediately (Phase 1 — anti-frontrunning)
4. Generates the VDF proof locally (computationally intensive — do not kill the process)
5. Auto-generates a Kinetic Identity Document (KID) for the name and saves it to `~/.local/share/kinetic/kids/`
6. Signs and submits the full proof to the local daemon
7. Saves `zones/<name>.json` and `zones/<name>.reveal.json`

**Expected time by name length:**

| Label length | Example | Approximate time |
|---|---|---|
| 8+ chars | `mywebsite.kin` | ~2 hours |
| 6 chars | `saifmu.kin` | ~12 hours |
| 4 chars | `saif.kin` | ~15 days |
| 2 chars | `sk.kin` | ~5 months |

::: warning Short names (≤6 chars)
For names 6 characters or shorter, the CLI prints a `CRITICAL WARNING` and waits 15 seconds before starting. Press `Ctrl+C` within that window to cancel. Once VDF computation starts, **all progress is lost if interrupted**.
:::

**Example:**
```bash
kinetic name register mywebsite.kin
```

**Example output:**
```
INFO  kinetic: Starting registration process for 'mywebsite.kin' (4194304 iterations)
INFO  kinetic: Fetching latest Drand entropy beacon...
INFO  kinetic: Successfully fetched Drand round 14281723.
INFO  kinetic: Broadcasting Commitment to DHT (Phase 1 of 2)...
INFO  kinetic: Commitment accepted. Starting VDF computation (Phase 2 of 2)...
INFO  kinetic: This domain requires 4194304 iterations and will take approximately 2.0 hours.
INFO  kinetic: VDF Proof successfully generated!
INFO  kinetic: Success! mywebsite.kin has been published to the Kinetic DHT network.
INFO  kinetic: Your zone configuration was saved to ~/.local/share/kinetic/zones/mywebsite.kin.json
INFO  kinetic: Your reveal proof was saved to ~/.local/share/kinetic/zones/mywebsite.kin.reveal.json
```

---

### `kinetic name publish`

Push your local DNS zone configuration to the decentralized network. Run this after editing your zone file (`zones/<name>.json`).

```bash
kinetic name publish <name>
```

**Arguments:**

| Argument | Required | Description |
|---|---|---|
| `<name>` | ✅ | The name to publish (e.g. `mywebsite.kin`) |

**Example:**
```bash
# 1. Edit your zone file
nano ~/.local/share/kinetic/zones/mywebsite.kin.json

# 2. Publish the updated zone
kinetic name publish mywebsite.kin
```

---

### `kinetic name renew`

Start a fresh VDF proof computation for an existing name. Renewal takes the same amount of time as the original registration.

```bash
kinetic name renew <name> [--iterations <n>]
```

**Arguments:**

| Argument | Required | Description |
|---|---|---|
| `<name>` | ✅ | The name to renew |
| `--iterations`, `-i` | ❌ | VDF iterations. Default: `4,194,304` |

::: tip When do I need to renew?
The daemon broadcasts a heartbeat automatically while it is running. You only need to manually renew if your daemon has been offline for an extended period (weeks to months). Day-to-day operation does not require renewal.
:::

---

### `kinetic name list`

List all `.kin` names owned by the local node.

```bash
kinetic name list
```

Queries the daemon API first. If the daemon is offline, falls back to reading the local `zones/` directory.

**Example output:**
```
INFO  kinetic: Names managed by local daemon:
INFO  kinetic: - mywebsite.kin
INFO  kinetic: - blog.kin
```

---

### `kinetic name info`

Show stored information about a specific `.kin` name.

```bash
kinetic name info <name>
```

Attempts to resolve from the network first. If the daemon is offline or the name is not yet published, reads from the local `zones/<name>.reveal.json` and displays:
- Drand pulse round at time of registration
- VDF iteration count
- Local vs network resolution status

**Example:**
```bash
kinetic name info mywebsite.kin
```

---

### `kinetic name resolve`

Resolve a `.kin` name from the network and print the full reveal record.

```bash
kinetic name resolve <name>
```

**Arguments:**

| Argument | Required | Description |
|---|---|---|
| `<name>` | ✅ | The name to resolve (e.g. `mywebsite.kin`) |

**Example:**
```bash
kinetic name resolve mywebsite.kin
```

---

## `kinetic identity`

Manages Kinetic Identity Documents (KIDs) — post-quantum cryptographic identity documents linked to `.kin` names. KIDs use **ML-DSA-65** (Module-Lattice Digital Signature Algorithm, NIST Level 3 post-quantum standard).

---

### `kinetic identity create`

Generate a new KID keypair and write the signed KID document to a JSON file.

```bash
kinetic identity create [--output <path>]
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--output`, `-o` | `kid.json` | Path to write the KID document |

**Files written:**
- `<output>` (e.g. `kid.json`) — signed KID document (JSON, share-safe)
- `<output>.key` (e.g. `kid.key`) — ML-DSA-65 private controller key (binary, `chmod 600`, **never share**)

**Example:**
```bash
kinetic identity create --output saif.kid.json
```

The KID document contains:
- `doc_type`: `"kinetic.kid.v1"`
- `kid`: a `did:kin:` identifier derived from the public key hash
- `controller_keys`: your ML-DSA-65 public key (base64url-encoded)
- `signature`: the document self-signed by your controller key

---

### `kinetic identity publish`

Sign and publish a KID document and/or Capability Manifest to the DHT network via the local daemon. Requires daemon to be running.

```bash
kinetic identity publish --name <name.kin> [--kid <path>] [--manifest <path>]
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--name` | *(required)* | The `.kin` domain name that owns this KID |
| `--kid` | `kid.json` | Path to the KID document JSON file |
| `--manifest` | `manifest.json` | Path to a Capability Manifest JSON file |

If `--kid` path does not exist, the KID publish step is skipped silently. Same for `--manifest`. At least one must exist.

**Example:**
```bash
kinetic identity publish --name saif.kin --kid saif.kid.json
```

---

### `kinetic identity resolve`

Resolve a `did:kin:` identity from the network.

```bash
kinetic identity resolve <did>
```

**Arguments:**

| Argument | Required | Description |
|---|---|---|
| `<did>` | ✅ | A `did:kin:` identifier (e.g. `did:kin:abc123...`) |

**Example:**
```bash
kinetic identity resolve did:kin:a1b2c3d4e5f6...
```

---

### `kinetic identity revoke`

Revoke a KID by setting its `deactivated` flag and re-signing with the revocation key. The revoked document can then be published to prevent anyone from trusting the old KID.

```bash
kinetic identity revoke --kid <path> --key <key-file> [--output <path>]
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--kid` | *(required)* | Path to the KID document to revoke |
| `--key` | *(required)* | Path to the binary controller key file (32-byte raw seed) |
| `--output`, `-o` | `revoked_kid.json` | Path to write the revoked KID document |

::: warning
The `--key` file must contain exactly 32 bytes (the raw ML-DSA-65 seed). This is the `.key` file created alongside your KID document.
:::

---

### `kinetic identity rotate-key`

Replace the primary controller key on an existing KID with a newly generated ML-DSA-65 keypair. The rotation is authorized by signing with the **old** controller key.

```bash
kinetic identity rotate-key --kid <path> --old-key <key-file> [--output <path>]
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--kid` | *(required)* | Path to the existing KID document |
| `--old-key` | *(required)* | Path to the current controller key file (32-byte raw seed) |
| `--output`, `-o` | `rotated_kid.json` | Path to write the updated KID document |

**Files written:**
- `<output>` — updated KID document, signed with the old key
- `<output>.key` — new ML-DSA-65 private key (binary, `chmod 600`)

---

## `kinetic governance`

Submit and sign post-quantum governance proposals to the Kinetic network. All proposals are signed with ML-DSA-65 keys and broadcast to the DHT.

::: warning Council / Root / Guard access required
These commands are for governance participants only. Running them without the appropriate signing authority will result in proposal rejection by the network. All flags default to the local `identity.key`.
:::

All governance commands accept a `--signer-key <path>` flag (default: `~/.local/share/kinetic/identity.key`).

---

### `kinetic governance appoint-member`

Appoint a new member to the Governance Council. Requires quorum of existing council signatures.

```bash
kinetic governance appoint-member <key> [--signer-key <path>]
```

`<key>` — hex-encoded ML-DSA-65 public key of the candidate (1952 bytes hex = 3904 hex chars).

---

### `kinetic governance remove-council-member`

Remove an existing member from the Governance Council. Requires quorum.

```bash
kinetic governance remove-council-member <target-key> [--signer-key <path>]
```

---

### `kinetic governance self-appoint-council-member`

Bootstrap self-appointment to the council. Only valid during genesis bootstrap. Rejected once the council is active.

```bash
kinetic governance self-appoint-council-member <candidate-key> [--signer-key <path>]
```

---

### `kinetic governance update-binary`

Propose a network-wide binary update. Requires quorum.

```bash
kinetic governance update-binary --file <release.json> [--signer-key <path>]
```

`release.json` must contain: `version`, `manifest_hash` (hex), `github_username`, `git_commit`, `git_branch`, `mirrors` (array of URLs).

---

### `kinetic governance veto-update`

Veto an active proposal. Requires one council member signature.

```bash
kinetic governance veto-update <target-hash> [--signer-key <path>]
```

`<target-hash>` — hex-encoded hash of the proposal to veto.

---

### `kinetic governance execute-timelock`

Execute a proposal whose timelock period has expired.

```bash
kinetic governance execute-timelock <target-hash> [--signer-key <path>]
```

---

### `kinetic governance lock-council`

Lock the council to prevent any further membership changes. Requires supermajority.

```bash
kinetic governance lock-council [--signer-key <path>]
```

---

### `kinetic governance rotate-root-key`

Rotate the network's overarching Root Key. Requires a valid Guard signature.

```bash
kinetic governance rotate-root-key <new-key> [--signer-key <path>]
```

---

### `kinetic governance rotate-guard-key`

Rotate the Guard Key. Requires a Root Key signature.

```bash
kinetic governance rotate-guard-key <new-key> [--signer-key <path>]
```

---

### `kinetic governance grant-premium-name`

Grant premium namespace rights for a specific apex name to a key. Requires council quorum.

```bash
kinetic governance grant-premium-name <name> <target-pubkey> [--signer-key <path>]
```

---

### `kinetic governance revoke-premium-name`

Revoke previously granted premium namespace rights. Requires council quorum.

```bash
kinetic governance revoke-premium-name <name> [--signer-key <path>]
```

---

## `kinetic dns-tree`

Generates a Cloudflare-ready Merkle DNS tree zone file from a list of libp2p Multiaddrs. Used by network operators to publish P2P bootstrap node discovery records in standard DNS.

### `kinetic dns-tree generate`

```bash
kinetic dns-tree generate --input <file> --output <file> --domain <domain>
```

**Flags:**

| Flag | Required | Description |
|---|---|---|
| `--input` | ✅ | Path to a file containing one libp2p Multiaddr per line |
| `--output` | ✅ | Path to write the generated DNS zone file (BIND zone format) |
| `--domain` | ✅ | Root domain to deploy the tree under (e.g. `seed.saifmukhtar.dev`) |

**What it does:**
1. Reads each Multiaddr from the input file (blank lines are skipped)
2. Hashes each address as a leaf node using SHA-256 → Base32 (first 32 chars)
3. Builds a Merkle tree upward, hashing branches in groups of up to 50
4. Writes the full tree as BIND-format `TXT` records to the output file:
   - Leaf: `<hash>.<domain>  IN  TXT  "kintree-leaf:<multiaddr>"`
   - Branch: `<hash>.<domain>  IN  TXT  "kintree-branch:<child-hashes>"`
   - Root: `<domain>  IN  TXT  "kintree-root:v1 e=<root-hash> seq=1"`

**Example:**
```bash
# Input file: bootstrap-nodes.txt
# /ip4/1.2.3.4/tcp/6070/p2p/12D3KooW...
# /ip4/5.6.7.8/tcp/6070/p2p/12D3KooW...

kinetic dns-tree generate \
  --input bootstrap-nodes.txt \
  --output seed.zone \
  --domain seed.saifmukhtar.dev
```

Upload `seed.zone` to your DNS provider as TXT records.

---

## `kinetic clock`

Display the current Kinetic Network Time, derived from the drand beacon round number.

```bash
kinetic clock [--listen]
```

**Flags:**

| Flag | Description |
|---|---|
| `--listen`, `-l` | Continuously print the time every 3 seconds (live clock mode) |

**Sync behavior:**
1. Attempts to fetch the current time from the local daemon API (`/api/time`)
2. If the daemon is offline, calculates the time mathematically from the local system clock using the drand genesis time and period constants

**Output format:**
```
🟢 [Synced] Kinetic Network Time: Round 14281723 — 2026-07-23 06:14:23 UTC
```
```
🔴 [Offline/Mathematical] Kinetic Network Time: Round 14281720 — 2026-07-23 06:14:08 UTC
```

**Live clock:**
```bash
kinetic clock --listen
```

---

## Global Behavior

### API Timeout

All commands that talk to the daemon use a **30-second HTTP timeout**. If your daemon is slow to respond (e.g. during a VDF computation), the timeout may trigger. This does not stop the daemon's work — only the CLI's wait for a response.

### Daemon Not Running

If the daemon is not running and a command requires it, you will see:

```
Failed to read API token from ~/.local/share/kinetic/api.token: No such file or directory.
Is kinetic-daemon running?
```

Start the daemon first: `kinetic daemon run` or `kinetic daemon start`.

### Binary Not Found

If a managed binary (`kinetic-daemon`, `kinetic-host`, `kinetic-node`, `kinetic-dns`) is not installed on your `PATH`, you will see:

```
Error: 'kinetic-daemon' is not installed on this system.

'kinetic-daemon' is needed to manage .kin domain names and run the local P2P proxy.
Install it and make sure it is available on your PATH, then re-run this command.
```

### Name Normalization

The `.kin` suffix is automatically appended if you omit it. `kinetic name register mysite` is equivalent to `kinetic name register mysite.kin`.
