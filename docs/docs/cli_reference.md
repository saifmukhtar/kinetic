# CLI Reference

The `kinetic` command-line tool provides a unified interface for managing names, identities, and background daemons on the Kinetic network.

This page explains all available commands and what they do.

---

## 1. Domain Names (`kinetic name`)

Commands for claiming, publishing, and managing your `.kin` (or custom TLD) domain names.

* **`kinetic name register <NAME>`**  
  Claims a name (e.g. `example.kin`) by fetching randomness from Drand, generating a blind commitment, and performing the VDF Proof-of-Time locally. This operation takes CPU time but costs zero dollars.

* **`kinetic name publish <NAME>`**  
  Pushes your local `.json` configuration file for the name to the decentralized network (DHT). Must be run after `register` and whenever you update your DNS records.

* **`kinetic name renew <NAME>`**  
  Renews a name you already own by submitting a fresh VDF proof to prevent expiration.

* **`kinetic name list`**  
  Lists all names you own that are tracked by your local daemon.

* **`kinetic name info <NAME>`**  
  Displays detailed status information (expiration, associated identity, current records) for a specific name you own.

* **`kinetic name resolve <NAME>`**  
  Performs a network lookup to find the records and identity attached to a specific name.

---

## 2. Kinetic Identities (`kinetic identity`)

Commands for managing Kinetic Identity Documents (KIDs) and Capability Manifests, which bind names to cryptographic public keys instead of central authorities.

* **`kinetic identity create --output <FILE>`**  
  Generates a new Ed25519 identity keypair and saves it locally. This identity is used to sign your domain ownership.

* **`kinetic identity publish --kid <FILE>`**  
  Publishes your Kinetic Identity Document (KID) to the network so that others can verify your signatures.

* **`kinetic identity resolve <DID>`**  
  Resolves a `did:kin:` identity string from the network and displays its public key and manifest.

---

## 3. Seed Management (`kinetic seed`)

* **`kinetic seed`**  
  Generates and backs up a secure master seed phrase for your local daemon instance.

---

## 4. Daemons & Infrastructure

These commands run background processes that power different ways of interacting with the Kinetic network.

* **`kinetic daemon [OPTIONS]`**  
  Starts the standard Kinetic Daemon. This process acts as a local proxy for name owners, runs the VDF proofs, and manages the local cache. Ideal for everyday users registering names.

* **`kinetic host [OPTIONS]`**  
  Starts the Kinetic Host. A lightweight binary meant for VPS instances and home labs that serves content or proxy traffic to the rest of the P2P network. It actively rotates its transport identity every few seconds to prevent targeted DDoS attacks.

* **`kinetic node [OPTIONS]`**  
  Starts a full Kinetic Node. This headless binary participates fully in the global Kademlia DHT, stores redundant data for other users, and validates Gossip traffic. Intended for network contributors and infrastructure providers.

* **`kinetic dns [OPTIONS]`**  
  Starts the Kinetic DNS Server. A lightweight local DNS server (listening on port 53, requires root/sudo) that intercepts `.kin` domain queries and routes them to the Kinetic P2P network, while passing standard queries (like `.com`) upstream.
