---
title: '06 — Daemon & DNS'
prev:
  text: '05 — Storage Engine'
  link: '/architecture/05-storage-engine'
next:
  text: '07 — Governance'
  link: '/architecture/07-governance'
---

# Architecture & Motivation: Daemon, DNS, and Proxy Interfaces

Kinetic is not a centralized cloud service; it is a protocol designed to run natively on the user's local machine. The `kinetic-daemon` is the beating heart of the system, acting as the critical bridge between legacy internet protocols (HTTP/DNS) that the user's browser understands, and the novel P2P DHT network that stores the decentralized records.

## The Local Axum API

To allow the user's CLI, UI dashboard, or custom automation scripts to interact with the P2P network (e.g., to register a name, update a record, or check balance), the daemon exposes a REST API built on the highly concurrent `axum` web framework, listening by default on port `16002`.

### Security Boundary: Localhost Binding and Bearer Tokens
Exposing an HTTP API locally is a massive security risk if not handled correctly. If a user visits a malicious website, the Javascript running on that page could attempt to make a background request (via fetch) to `http://127.0.0.1:16002/delete-domain` and silently hijack the user's assets. This is known as a Cross-Site Request Forgery (CSRF).

To categorically secure the daemon against this:
1. **Hard Binding:** The API strictly binds to the loopback interface (`127.0.0.1`). It will aggressively refuse to listen on `0.0.0.0` (all interfaces) unless explicitly overridden by a server administrator with a specific flag, preventing devices on the local Wi-Fi from arbitrarily commanding the daemon.
2. **Bearer Token Authentication:** Just binding to localhost is insufficient to stop a browser from executing a CSRF attack on the local machine. Therefore, the daemon generates a cryptographically random 256-bit `api.token` on startup and saves it to a securely permissioned directory (only readable by the owner). Every single API request must include this exact token in the `Authorization: Bearer` header. The browser cannot guess this token, completely neutralizing the attack vector.

## Split-DNS over Port 53

Standard web browsers (Chrome, Firefox, Safari) do not inherently know how to resolve `.kin` domains. They query the operating system, which in turn queries whatever DNS server the network router provides.

To make `.kin` websites load seamlessly in the browser just like `.com` sites, Kinetic runs a local DNS resolver built on top of the high-performance `hickory-dns` library (formerly Trust-DNS).

### Why Sudo and Port 53?
The global DNS protocol operates on port 53 (UDP/TCP). Modern UNIX-like networking stacks require root or Administrator privileges to bind to any port below 1024. This is why the Kinetic daemon often requires `sudo` or elevated execution policies on Windows to initialize the DNS subsystem. 

### The Split-DNS Architecture
When the daemon takes over port 53, it acts as a **Split-DNS proxy**:
- When the user's OS asks `127.0.0.1:53` to resolve `google.com`, the Kinetic daemon recognizes it is a standard ICANN TLD. It acts as a transparent proxy, seamlessly forwarding the request to Cloudflare (`1.1.1.1`), Google (`8.8.8.8`), or the system's previously configured default upstream resolver.
- When the OS asks for `myname.kin`, the daemon intercepts the request. It halts the upstream query, queries the local Kinetic DHT cache, verifies the cryptographic signature of the `.kin` record, and returns the resulting IP address back to the OS.

### The Rebinding Threat
If Kinetic's DNS proxy didn't carefully validate the responses returned by the DHT, an attacker could register a `.kin` domain, point its `A` record to `127.0.0.1` or a private subnet IP (`192.168.1.1`), and trick the user's browser into executing an SSRF (Server-Side Request Forgery) or DNS Rebinding attack against the user's own local router or background services.

To mitigate this, Kinetic aggressively filters local/loopback IPs returned by untrusted DHT records. If an attacker's domain points to a local IP, the Kinetic resolver will rewrite the response to a blackhole IP (like `0.0.0.0`), neutralizing the threat.

## The HTTP Proxy

DNS only provides an IP address. However, many decentralized `.kin` websites are not hosted on traditional web servers; they are hosted on Content Addressable P2P file systems (like IPFS) or behind gateways that require specific HTTP `Host` headers to route traffic to the correct bucket.

To solve this, the daemon can optionally spin up a local HTTP/HTTPS proxy.

When the proxy is enabled (typically configured in the OS network settings), all web traffic to `.kin` domains routes through the daemon's proxy layer. The daemon fetches the raw HTML, CSS, and Javascript assets directly from the underlying P2P network (or IPFS gateway) and streams them dynamically to the browser. This architecture allows fully decentralized, serverless websites to render instantly in a standard web browser without requiring the user to install complex browser extensions or modify their browser settings.
