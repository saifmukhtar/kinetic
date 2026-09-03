# kinetic-nrs

**The Name Resolution System (NRS) for the Kinetic Network.**

`kinetic-nrs` is the built-in UDP/TCP DNS resolver daemon for Kinetic. It acts as a bridge between standard operating systems and the decentralized Kinetic Name Difficulty Coefficient (NDC) identity system.

By binding directly to port `53`, `kinetic-nrs` intercepts DNS queries for your configured namespace (e.g., `.kin` domains) and safely forwards non-Kinetic queries to global public DNS resolvers. 

## Features

- **Decentralized DNS**: Resolves decentralized `.kin` domains directly from your local node's routing tables and databases.
- **Record Types**: Supports `A`, `AAAA`, `CNAME`, and `TXT` records, as well as native Kinetic records (`IPFS`, `KID`, `PEERID`).
- **Security & Privilege Dropping**: On Unix systems, it automatically binds to port 53 as `root` and then gracefully drops privileges to the `nobody` user using `privdrop`, ensuring the daemon runs with maximum safety.
- **SSRF Protection**: Includes robust network filtering (`kinetic_core::net::validate_ssrf_safe`) to ensure malicious DNS records cannot loopback or scan your internal network (e.g., rejecting `127.0.0.1` or `169.254.169.254` answers).
- **High Performance Caching**: Powered by `moka`, queries are asynchronously cached to prevent cache stampedes and minimize latency on repeated DNS lookups.
- **DoH Fallback**: Uses `hickory-resolver` over DNS-over-HTTPS (DoH) to forward and resolve normal internet traffic, meaning you can safely set your machine's primary DNS to `127.0.0.1`.

## Architecture

1. **UDP/TCP Binding**: Listens on port `53` via `hickory-server`.
2. **Local HTTP Query**: When a `.kin` request comes in, it queries the local `kinetic-host` or `kinetic-daemon` backend (default port `16001`) via a fast internal HTTP request using `reqwest`.
3. **Cryptographic Verification**: Signatures on standard DNS records are verified using `kinetic-verify` before being served to the OS.
