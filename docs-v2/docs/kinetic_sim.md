# Chapter 13: Kinetic Simulation Sandbox

This directory contains the full local simulation environment for **Kinetic**, a decentralized DNS and web hosting network built on Kademlia DHT. It orchestrates 50 autonomous nodes running inside isolated containers to test real-world network conditions, domain registration, and hosting failovers.

## 1. Architecture & Core Components

The simulation consists of the following structure:
* **10 DHT Nodes** (`DHT-Node`): Form the backbone of the decentralized hash table for resolving domains.
* **6 CDN Hosts** (`CDN-Host`): Provide decentralized web hosting, negotiating capacity with users.
* **34 User Daemons** (`UserDaemon`): AI-driven client agents that register identities (KIDs), compute VDF proofs to claim domains, and publish websites.
* **Orchestrator** (`orchestrator.py`): The central Python controller that manages the simulation lifecycle across 9 distinct phases.
* **Dashboard** (`kinetic-dashboard/`): A real-time React/Vite dashboard visually representing the state of the network.

## 2. "Our Tricks" (How the Simulation Works)

Because we are simulating a massive decentralized blockchain-like system purely using local containers, we implemented a few clever tricks to make the simulation both realistic and reliable:

1. **The Subprocess/Exec Bridge:** Instead of relying on a fragile API between the Python orchestrator and the containers, the orchestrator directly executes the real `kinetic-cli` Rust binaries inside the containers using `podman exec`. This guarantees that the network operates exactly as it would in production.
2. **The `jackpot.kin` Conflict Lock:** To test the network's resilience to naming conflicts, Daemons #1 and #2 both attempt to register the highly coveted domain `jackpot.kin` simultaneously. Because our local Kademlia DHT doesn't inherently enforce VDF (Verifiable Delay Function) consensus rules by itself, the last writer would normally overwrite the first. To accurately simulate a real blockchain consensus rejection, we implemented a strict python lock (`_jackpot_winner_lock`) in `daemon_agent.py`. The first daemon to successfully verify their domain secures the lock, explicitly forcing the slower daemon into a `conflict_lost` state.
3. **Seamless Failover & Auto-Retry:** When a daemon detects it lost a conflict, it automatically falls back to its own name prefix (e.g., `bob.kin`), negotiates with its host to rename its web directory so no files are lost, and immediately retries the registration process.
4. **AI Personas (Ollama):** We inject an element of human realism by assigning each daemon a persona (e.g., "Alice — Startup Founder", "Bob — Privacy Advocate"). Between technical CLI executions, we query a local Ollama model to generate contextual, one-sentence thoughts about what they are doing, bringing the simulation to life on the dashboard.

## 3. How to Run the Simulation

The simulation is located in the `kinetic-sim/` directory.

### Pre-flight Setup & Build
Generate the simulation keys and deploy the containerlab topology:
```bash
# Ensure you are in the kinetic-sim directory
python3 setup_sim.py

# Build the images and deploy the 50 containers
./deploy.sh
```

### Start the Orchestrator
Launch the brain of the simulation. This will boot the nodes and start the lifecycle phases:
```bash
sudo PYTHONPATH="/$HOME/$USER/.local/lib/python3.14/site-packages" python3 orchestrator.py
```

### Start the Dashboard
In a separate terminal, launch the frontend to watch the simulation unfold:
```bash
cd kinetic-dashboard
npm install
npm run dev
```

## 4. Teardown

When you are finished running the simulation, you can easily destroy the 50 containers and network topology by running:
```bash
sudo containerlab destroy -t topology.clab.yml --runtime podman
```
