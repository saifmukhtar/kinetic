# kinetic-daemon

**The background service and REST API gateway for local node administration and routing.**

`kinetic-daemon` is the localized administrative controller for a Kinetic node. It runs in the background and exposes a secure HTTPS REST API (default port `16002`) to coordinate name resolution, key management, telemetry, and node lifecycle events.

While `kinetic-host` manages external proxying and `kinetic-network` manages the P2P swarm, `kinetic-daemon` provides the command-and-control surface for the CLI and user applications.

## Features

- **Secure REST API**: Exposes an `axum`-based HTTPS API bounded by a dynamically generated, cryptographically secure Bearer token.
- **Local CA & TLS**: Uses `rcgen` and `rustls` to automatically generate a localized Root Certificate Authority (CA) and issues self-signed TLS certificates for `localhost`, ensuring all CLI-to-daemon communication is end-to-end encrypted.
- **Constant-time Auth**: Employs `subtle::ConstantTimeEq` when validating API Bearer tokens to protect the daemon against timing side-channel attacks.
- **Governance Mutations**: Exposes endpoints for users to craft, sign, and broadcast Governance and VDF payloads onto the network.
- **IPC & System Daemon**: Can be installed as a permanent system service via `service-manager`, keeping the local Kinetic node online and routing traffic seamlessly across system reboots.
- **Local DNS & Gateway**: Interfaces with `hickory-server` and `axum` routing layers to bridge IPFS CIDs and traditional DNS queries safely.
