# Architecture & Motivation: Daemon, DNS, and Proxy Interfaces

Kinetic is not a cloud service; it runs on the user's local machine. The `kinetic-daemon` is the beating heart of the system, acting as the bridge between legacy internet protocols (HTTP/DNS) and the P2P network.

## The Local Axum API

To allow the user's CLI, UI, or local scripts to interact with the P2P network, the daemon exposes a REST API built on the `axum` framework, listening on port `16002`.

### Security Boundary: Localhost Binding and Bearer Tokens
A local API is a massive security risk if a malicious website can access it via a browser script (Cross-Site Request Forgery). 

To secure this:
1. **Hard Binding:** The API strictly binds to `127.0.0.1`. It will refuse to listen on `0.0.0.0` (all interfaces) unless explicitly overridden for advanced server deployments.
2. **Bearer Token Authentication:** Just binding to localhost is not enough to stop a malicious webpage running Javascript on the local machine. The daemon generates a random `api.token` on startup and saves it to the local secure directory. Every API request must include this token in the `Authorization: Bearer` header.

## Split-DNS over Port 53

Browsers (Chrome, Firefox) do not know how to resolve `.kin` domains. To make `.kin` websites natively load in the browser, Kinetic runs a local DNS resolver (`kinetic-dns`).

### Why Sudo and Port 53?
DNS operates on port 53. OS networking stacks require root/Administrator privileges to bind to ports below 1024. This is why the Kinetic daemon often requires `sudo` or elevated privileges to start the DNS subsystem.

### The Rebinding Threat
When the user's OS asks `127.0.0.1:53` to resolve `google.com`, the Kinetic daemon acts as a proxy, forwarding the request to Cloudflare (`1.1.1.1`) or the system's default upstream resolver. When it asks for `myname.kin`, the daemon intercepts it and queries the DHT.

If Kinetic's DNS proxy didn't carefully validate responses, an attacker could register a `.kin` domain, point its `A` record to `127.0.0.1`, and trick the user's browser into executing an SSRF (Server-Side Request Forgery) or DNS Rebinding attack against the user's own local services.
Kinetic mitigates this by aggressively filtering local/loopback IPs returned by untrusted DHT records unless the user explicitly whitelists the domain for local development.

## The HTTP Proxy

DNS only provides an IP address. But many `.kin` websites are hosted on P2P file systems (like IPFS) or behind gateways that require HTTP Host headers. To solve this, the daemon can spin up a local HTTP/HTTPS proxy.

When the proxy is enabled, all traffic to `.kin` domains goes through the daemon. The daemon fetches the raw HTML/assets from the P2P network and streams them to the browser. This allows fully decentralized websites to render instantly in a standard web browser without requiring the user to install a browser extension.
