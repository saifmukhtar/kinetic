# Chapter 11: Getting Started (Installation & Quickstart)

If you have made it through the intense mathematical theory and exhaustive code breakdowns of the previous chapters, you are ready to physically deploy Kinetic. 

This final chapter serves as the hands-on, practical guide to compiling the workspace from source, launching the background daemon, and successfully registering your very first decentralized `.kin` domain.

---

## 1. System Prerequisites

Kinetic relies heavily on advanced cryptographic engines and systems-level networking. Before compiling, ensure your local environment is correctly configured.

### Required Toolchains
1. **Rust:** You must have the standard Rust toolchain (`cargo`, `rustc`) installed via [rustup](https://rustup.rs/).
2. **C++ Compiler:** The `chiavdf` FFI bindings require a modern C++ compiler (e.g., `g++` or `clang`).
3. **GMP Library:** The Chia VDF engine relies on the GNU Multiple Precision Arithmetic Library for hyper-fast large integer mathematics.

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install build-essential cmake libgmp-dev
```

**macOS (via Homebrew):**
```bash
brew install cmake gmp
```

---

## 2. Compiling the Workspace

Clone the repository and compile the workspace in release mode. The VDF grind is highly sensitive to compiler optimizations; running it in debug mode will make domain registrations unbearably slow.

```bash
git clone https://github.com/saifmukhtar/kinetic.git
cd kinetic
cargo build --release
```

This command will compile all the major crates (`kinetic-core`, `kinetic-network`, `kinetic-vdf`, `kinetic-dns`, and `kinetic-storage`), linking the C++ Chia VDF engine via `build.rs`, and finally producing the `kinetic-daemon` and `kinetic-cli` binaries.

---

## 3. Launching the Kinetic Daemon

The `kinetic-daemon` must run continuously in the background. It serves three critical functions:
1. Acting as your local Kademlia DHT peer.
2. Intercepting port `53` to provide seamless Split-DNS to your browser.
3. Serving the embedded **Kinetic UI** via its local Axum HTTP server.

Because binding to port `53` (the standard DNS port) is a privileged operation on Linux and macOS, you **must** run the daemon with `sudo` or administrator privileges.

### Running the Daemon
In a dedicated terminal window (or configured via a `systemd` service file):

```bash
sudo ./target/release/kinetic-daemon
```

*Note: In future production releases, the daemon will automatically drop privileges to a restricted `kinetic` user account immediately after binding to port 53, ensuring maximum system security.*

Once running, the daemon will output logs indicating it has connected to the bootstrap DHT swarm, initialized its auto-healing local Sled database, and bound the local REST API to `127.0.0.1:16001`.

---

## 4. The Kinetic UI Dashboard

With the daemon running, the absolute easiest way to manage your domains and network connections is via the bundled **Kinetic UI**. 

The UI is a sleek React SPA served directly out of the daemon's binary memory using `rust-embed`.

Open your browser and navigate to:
**http://localhost:16001**

From this dashboard, you can:
- Track DHT node discovery.
- View real-time Hashcash memory pool workers.
- Graphically register new domains and watch the VDF progress bar.

---

## 5. Registering Your First Domain (CLI Workflow)

If you prefer the command line over the web UI, you can use the `kinetic-cli` to claim territory on the network. This process uses the new **Two-Phase Commit/Reveal Protocol** to prevent front-running.

Open a separate terminal window. You do *not* need `sudo` for the CLI.

### Phase 1: The Commit & Grind
To register `mywebsite.kin`, simply type:

```bash
./target/release/kinetic-cli register mywebsite.kin
```

### What Happens Next?
1. The CLI contacts the external Drand beacon to pull down the latest entropy pulse.
2. It hashes your requested name, a random salt, the Drand pulse, and your Ed25519 public key into a blind commitment, instantly broadcasting it to the DHT.
3. **The Grind:** The CLI spins up a system-wide mutex lock (`fs2::FileExt`) and computes the VDF. Your CPU fan may spin up. Depending on the name length, this takes a few seconds to a few hours.
4. **The Reveal Generation:** Once the VDF proof is generated, the CLI creates a local JSON template and saves your mathematical proof to `~/.config/kinetic/zones/mywebsite.kin.reveal.json`.

### Phase 2: Configuration & Publishing
Now, open the newly generated `~/.config/kinetic/zones/mywebsite.kin.json` configuration file in a text editor and add the IP address of your web server as an `A` record.

Once you have configured the zone file, publish your records and your cryptographic reveal to the global swarm:

```bash
./target/release/kinetic-cli publish mywebsite.kin
```

Your name is instantly live globally!

---

## 6. Testing the Resolution

Because you are running the daemon locally, you can instantly test it without waiting for global DNS propagation.

### Testing with `dig`
Use the standard network utility `dig` to query your local machine on port `53`.

```bash
dig @127.0.0.1 mywebsite.kin A
```

You should receive an instantaneous response showing the `A` record you just configured.

### Testing in the Browser
Because the daemon has updated your OS loopback, you can bypass the terminal entirely.

Open Google Chrome or Mozilla Firefox and type `http://mywebsite.kin` into the URL bar. 

The browser will implicitly ask your local OS for the IP address. The OS will ask the `kinetic-daemon` on port 53. The daemon will realize it is a `.kin` domain, query the Kademlia DHT, verify the mathematics, and seamlessly route your browser to your local web server.

### Testing Legacy Pass-Through
To verify that the daemon hasn't broken your normal internet connection, try pinging a standard website:

```bash
dig @127.0.0.1 github.com A
```

The daemon uses `hickory_resolver` to instantly recognize that `github.com` does not end in `.kin` and forwards the request to Cloudflare (`1.1.1.1`), returning the standard public IP while strictly dropping malicious SSRF requests to internal interfaces.

---

## Welcome to the Sovereign Web

You have just registered a domain name without a credit card, without creating a username, and without asking permission from a corporation or government. Your ownership of that name is secured entirely by the unyielding laws of thermodynamics and cryptography, and your resolution traffic is immune to ISP censorship.

Welcome to Kinetic. The internet is yours again.
