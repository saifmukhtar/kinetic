# Chapter 10: Getting Started (Installation & Quickstart)

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
git clone https://github.com/your-org/kinetic.git
cd kinetic
cargo build --release
```

This command will compile all five major crates (`kinetic-core`, `kinetic-network`, `kinetic-vdf`, `kinetic-dns`, and `kinetic-storage`), linking the C++ Chia VDF engine via `build.rs`, and finally producing the `kinetic-daemon` and `kinetic-cli` binaries.

---

## 3. Launching the Kinetic Daemon

The `kinetic-daemon` must run continuously in the background. It serves three critical functions:
1. Acting as your local Kademlia DHT peer.
2. Maintaining the passive 60-second Sled Heartbeat loop for your domains.
3. Intercepting port `53` to provide seamless Split-DNS to your browser.

Because binding to port `53` (the standard DNS port) is a privileged operation on Linux and macOS, you **must** run the daemon with `sudo` or administrator privileges.

### Running the Daemon
In a dedicated terminal window (or configured via a `systemd` service file):

```bash
sudo ./target/release/kinetic-daemon
```

*Note: In future production releases, the daemon will automatically drop privileges to a restricted `kinetic` user account immediately after binding to port 53, ensuring maximum system security.*

Once running, the daemon will output logs indicating it has connected to the bootstrap DHT swarm, initialized its local Sled database at `/tmp/kinetic_db`, and bound the local REST API to `127.0.0.1:16001`.

---

## 4. Registering Your First Domain

With the daemon silently protecting your system and routing traffic in the background, you can now use the `kinetic-cli` to claim territory on the network.

Open a separate terminal window. You do *not* need `sudo` for the CLI.

### The Registration Command
Let's assume you want to register `mywebsite.kin` and point it to a local development server running on `192.168.1.100`.

```bash
./target/release/kinetic-cli register mywebsite.kin 192.168.1.100
```

### What Happens Next?
1. The CLI contacts the external Drand beacon to pull down the latest, unpredictable entropy pulse.
2. It hashes your requested name, the Drand pulse, and your Ed25519 public key into a blind commitment.
3. It determines the string length of `mywebsite.kin` and calculates the required squatter penalty (e.g., 500,000 VDF iterations).
4. **The Grind:** The CLI will pause. Your CPU fan may spin up. Depending on your hardware and the required iterations, this could take anywhere from a few seconds to a few minutes.
5. **The Reveal:** Once the VDF proof is successfully mathematically generated, the CLI signs the payload and posts it to the local daemon via `http://127.0.0.1:16001`.
6. The daemon saves it to the Sled database and unleashes the payload onto the global Kademlia swarm.

---

## 5. Testing the Resolution

If the registration was successful, the domain is now globally available. However, because you are running the daemon locally, you can instantly test it without waiting for global DNS propagation.

### Testing with `dig`
Use the standard network utility `dig` to query your local machine on port `53`.

```bash
dig @127.0.0.1 mywebsite.kin A
```

You should receive an instantaneous response showing an `A` record pointing to `192.168.1.100`.

### Testing in the Browser
Because the daemon has updated your OS loopback, you can bypass the terminal entirely.

Open Google Chrome or Mozilla Firefox and type `http://mywebsite.kin` into the URL bar. 

The browser will implicitly ask your local OS for the IP address. The OS will ask the `kinetic-daemon` on port 53. The daemon will realize it is a `.kin` domain, query the Kademlia DHT, verify the mathematics, and seamlessly route your browser to your local web server.

### Testing Legacy Pass-Through
To verify that the daemon hasn't broken your normal internet connection, try pinging a standard website:

```bash
dig @127.0.0.1 github.com A
```

The daemon will instantly recognize that `github.com` does not end in `.kin` and forward the request to Cloudflare (`1.1.1.1`) or Google (`8.8.8.8`), returning the standard public IP.

---

## Welcome to the Sovereign Web

You have just registered a domain name without a credit card, without creating a username, and without asking permission from a corporation or government. Your ownership of that name is secured entirely by the unyielding laws of thermodynamics and cryptography, and your resolution traffic is immune to ISP censorship.

Welcome to Kinetic. The internet is yours again.
