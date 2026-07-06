"""
agents/node_agent.py — NodeAgent: manages all 10 DHT infrastructure nodes.

Responsibilities:
  1. Phase 1 gatekeeper: boot all nodes and wait until they are P2P-connected.
  2. Periodic narrative generation via Ollama (non-blocking, separate thread).
  3. Health polling loop for the dashboard.

Containers: clab-kinetic-swarm-node{1..10}
Health API:  GET http://172.21.10.{i}:16003/health
"""

import subprocess
import threading
import time
import random
import requests

import ollama_client
from sim_state import registry, NodeState

# ─────────────────────────────────────────────────────────────────────────────
# Node personas — gives each node a distinct "personality" for Ollama narratives
# ─────────────────────────────────────────────────────────────────────────────
NODE_PERSONAS = [
    "a stoic routing backbone that never drops a packet",
    "an eager newcomer that aggressively caches Kademlia records",
    "a veteran node that has seen every eclipse attack attempt",
    "a geographically distant relay that bridges two network segments",
    "a high-bandwidth node co-located in a data centre",
    "a paranoid validator that double-checks every PoW proof",
    "a resilient node that continues routing even under heavy load",
    "a specialized node focused on heartbeat relay and watchtower tokens",
    "a fast but ephemeral node that mines new S/Kademlia keypairs aggressively",
    "a well-connected super-peer that maintains hundreds of open connections",
]

CONTAINER_PREFIX = "clab-kinetic-swarm"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _node_ip(idx: int) -> str:
    return f"172.21.10.{idx}"

def _health_url(idx: int) -> str:
    return f"http://{_node_ip(idx)}:16003/health"

def _is_healthy(idx: int) -> bool:
    try:
        r = subprocess.run(
            ["podman", "exec", f"{CONTAINER_PREFIX}-node{idx}", "curl", "-s", "-f", "http://127.0.0.1:16003/health"],
            capture_output=True, text=True, timeout=5
        )
        return r.returncode == 0
    except Exception:
        return False

def _log(msg: str, source: str = "NodeAgent"):
    registry.log("node", source, msg)

# ─────────────────────────────────────────────────────────────────────────────
# NodeAgent
# ─────────────────────────────────────────────────────────────────────────────

class NodeAgent:
    """
    Owns all 10 infrastructure nodes.

    Usage:
        agent = NodeAgent()
        agent.boot_all()          # blocks until all nodes are healthy
        agent.start_narrative()   # launches background narrative thread
    """

    def __init__(self):
        self._narrative_thread: threading.Thread | None = None
        self._stop_flag = threading.Event()

    # ── Phase 1: Boot & wait ─────────────────────────────────────────────

    def boot_all(self, timeout_per_node: float = 120.0):
        """
        Nodes are already launched by containerlab (kinetic-node runs in entrypoint.sh).
        We only need to wait until their /health endpoint responds — that confirms:
          - kinetic-node process started
          - S/Kademlia keypair loaded
          - P2P swarm connected to bootstrap peers
        """
        _log("Waiting for all 10 nodes to report healthy...")

        start = time.monotonic()
        pending = set(range(1, 11))

        while pending:
            elapsed = time.monotonic() - start
            if elapsed > timeout_per_node:
                failed = sorted(pending)
                for idx in failed:
                    registry.set_node_state(idx, NodeState.ERROR)
                    _log(f"Node {idx} timed out — marking ERROR", source=f"Node-{idx}")
                raise TimeoutError(f"Nodes {failed} did not come healthy in {timeout_per_node}s")

            still_pending = set()
            for idx in pending:
                if _is_healthy(idx):
                    registry.set_node_state(idx, NodeState.SYNCED)
                    _log(f"Node {idx} is healthy and synced to the DHT.", source=f"DHT-Node-{idx}")
                else:
                    still_pending.add(idx)

            pending = still_pending
            if pending:
                time.sleep(2)

        _log(f"All 10 nodes healthy. DHT backbone is live.")

    # ── Narrative loop ───────────────────────────────────────────────────

    def start_narrative(self):
        """Launch background thread that generates DHT-health narratives."""
        self._narrative_thread = threading.Thread(
            target=self._narrative_loop, daemon=True, name="NodeNarrative"
        )
        self._narrative_thread.start()

    def _narrative_loop(self):
        while not self._stop_flag.is_set():
            idx = random.randint(1, 10)
            persona = NODE_PERSONAS[idx - 1]

            current_state = registry.node_states.get(idx, NodeState.BOOTING)
            if current_state not in (NodeState.SYNCED, NodeState.ROUTING):
                time.sleep(10)
                continue

            # Build a contextual prompt based on what the sim is actually doing
            phase      = registry.current_phase
            phase_name = registry.phase_names.get(phase, "?")
            alive_daemons = sum(
                1 for s in registry.daemon_states.values()
                if s.name in ("ALIVE", "HEARTBEATING", "VERIFYING_DNS", "PUBLISHING")
            )

            system = (
                f"You are infrastructure Node {idx} in the Kinetic decentralized DNS network. "
                f"Your personality: {persona}. "
                f"The network is currently in Phase {phase} ({phase_name}). "
                f"There are {alive_daemons} active domain owners publishing records. "
                "Output ONLY a JSON object with keys: "
                "'dht_action' (short technical action, e.g. 'Storing Record', 'Validating PoW', "
                "'Relaying Heartbeat', 'Pruning stale DHT entries') "
                "and 'log_message' (one technical sentence describing what you are doing)."
            )
            user = "Report your current DHT operation."

            data = ollama_client.query(system, user, required_keys=["dht_action", "log_message"])
            if data:
                action = data["dht_action"]
                msg    = data["log_message"]
                registry.set_node_state(idx, NodeState.ROUTING)
                _log(f"[{action}] {msg}", source=f"DHT-Node-{idx}")

            # Stagger to avoid all 10 nodes hammering Ollama simultaneously
            time.sleep(random.uniform(30, 70))

    def stop(self):
        self._stop_flag.set()
