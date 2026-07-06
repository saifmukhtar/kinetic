"""
agents/host_agent.py — HostAgent: manages all 6 CDN/proxy hosts.

Responsibilities:
  1. Phase 2 gatekeeper: boot all hosts, resolve their peer_ids from /peer_id.
  2. Hosting negotiation: accept/reject daemon HOSTING_REQUEST messages.
  3. Website scaffolding: create per-domain HTML inside the container.
  4. Periodic traffic narrative via Ollama.

Containers: clab-kinetic-swarm-host{1..6}
Health API:  GET http://172.21.30.{i}:16004/health
Peer ID:     GET http://172.21.30.{i}:16004/peer_id
Backend:     python3 -m http.server 80 running inside container
"""

import json
import subprocess
import threading
import time
import random
import requests

import ollama_client
from sim_state import registry, HostState, HostingRequest, HostingAccepted, HostingRejected

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

HOST_CAPACITY = 6          # max domains per host (6 hosts × 6 = 36 > 34 daemons — some breathing room)
CONTAINER_PREFIX = "clab-kinetic-swarm"

HOST_PERSONAS = [
    "a premium CDN provider with top-tier SLA guarantees",
    "a community-run host collective with free hosting for open-source projects",
    "a high-throughput edge node specializing in media delivery",
    "a privacy-focused hosting provider that logs nothing",
    "a geo-distributed host with nodes in 12 countries",
    "a developer-centric host with instant deploy pipelines",
]

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _host_ip(idx: int) -> str:
    return f"172.21.30.{idx}"

def _health_url(idx: int) -> str:
    return f"http://{_host_ip(idx)}:16004/health"

def _peer_id_url(idx: int) -> str:
    return f"http://{_host_ip(idx)}:16004/peer_id"

def _is_healthy(idx: int) -> bool:
    """
    Primary: exec into the container and grep the kinetic-host log for the
    'listening' line that proves the API is up — no external port needed.
    Fallback: hit the actual HTTP /health endpoint (works once port is open).
    """
    container = f"{CONTAINER_PREFIX}-host{idx}"
    # kinetic-host prints "Starting API server on http://..." once it's bound
    result = subprocess.run(
        ["sudo", "podman", "exec", container,
         "sh", "-c",
         "grep -q 'P2P Network architecture wired' /tmp/host.log 2>/dev/null"],
        capture_output=True, timeout=5
    )
    if result.returncode == 0:
        return True
    # Fallback: try the actual HTTP endpoint (succeeds once port is bound)
    try:
        r = subprocess.run(
            ["sudo", "podman", "exec", container, "curl", "-s", "-f", "http://127.0.0.1:16004/health"],
            capture_output=True, text=True, timeout=5
        )
        return r.returncode == 0
    except Exception:
        return False

def _get_peer_id(idx: int) -> str | None:
    try:
        r = subprocess.run(
            ["sudo", "podman", "exec", f"{CONTAINER_PREFIX}-host{idx}", "curl", "-s", "-f", "http://127.0.0.1:16004/peer_id"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            return r.stdout.strip().strip('"')
    except Exception:
        pass
    return None

def _exec(role: str, idx: int, cmd: list[str]) -> tuple[str, str]:
    """Execute a whitelisted command inside a containerlab container."""
    safe = {"kinetic-cli", "python3", "mkdir", "echo", "cat", "sh", "bash"}
    if cmd[0] not in safe:
        return "", f"BLOCKED: {cmd[0]}"
    container = f"{CONTAINER_PREFIX}-{role}{idx}"
    full = ["sudo", "podman", "exec", container] + cmd
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=60)
        return r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT"
    except Exception as e:
        return "", str(e)

def _log(msg: str, source: str = "HostAgent"):
    registry.log("host", source, msg)

# ─────────────────────────────────────────────────────────────────────────────
# HostAgent
# ─────────────────────────────────────────────────────────────────────────────

class HostAgent:
    """
    Owns all 6 CDN/proxy hosts.

    Usage:
        agent = HostAgent()
        agent.boot_all()              # blocks until all hosts healthy + peer_ids fetched
        agent.start_negotiator()      # launches negotiation thread (drains inboxes)
        agent.start_narrative()       # launches Ollama traffic narrative thread
    """

    def __init__(self):
        self._hosted: dict[int, list[str]] = {i: [] for i in range(1, 7)}  # host_id → [domains]
        self._stop_flag = threading.Event()

    # ── Phase 2: Boot & wait ─────────────────────────────────────────────

    def boot_all(self, timeout: float = 600.0):
        """
        Wait for all 6 host containers to:
          1. Report healthy (via exec log-grep OR /health HTTP)
          2. Expose a valid peer_id on /peer_id
          3. Have python3 -m http.server 80 running (we start it if not)

        Timeout is 600s (10 min) because all 40 containers (hosts + daemons)
        share a single mining lock. Hosts can end up queued behind daemons.
        """
        _log("Waiting for all 6 hosts to report healthy and expose peer_id...")

        start   = time.monotonic()
        pending = set(range(1, 7))

        while pending:
            if time.monotonic() - start > timeout:
                for idx in pending:
                    registry.set_host_state(idx, HostState.ERROR)
                raise TimeoutError(f"Hosts {sorted(pending)} did not come up in {timeout}s")

            still_pending = set()
            for idx in pending:
                if not _is_healthy(idx):
                    still_pending.add(idx)
                    continue

                peer_id = _get_peer_id(idx)
                if not peer_id or peer_id == "UNKNOWN":
                    still_pending.add(idx)
                    continue

                # Host is up — register its peer_id and scaffold the web server
                registry.register_host_peer_id(idx, peer_id)
                registry.set_host_state(idx, HostState.READY)
                _log(
                    f"Host {idx} is READY. PeerID={peer_id[:20]}... "
                    f"Capacity: 0/{HOST_CAPACITY}",
                    source=f"CDN-Host-{idx}"
                )
                self._scaffold_webserver(idx)

            pending = still_pending
            if pending:
                time.sleep(3)

        _log("All 6 hosts healthy. Negotiation layer is open.")

    def _scaffold_webserver(self, idx: int):
        """Ensure /var/www exists and python3 http.server is running on port 80."""
        _exec("host", idx, ["mkdir", "-p", "/var/www"])
        # Check if already running; if not, start it
        _exec("host", idx, [
            "sh", "-c",
            "pgrep -f 'http.server 80' || python3 -m http.server 80 --directory /var/www > /dev/null 2>&1 &"
        ])

    # ── Phase 5: Hosting negotiation ─────────────────────────────────────

    def start_negotiator(self):
        """Launch a thread that drains host inboxes and responds to daemons."""
        t = threading.Thread(target=self._negotiation_loop, daemon=True, name="HostNegotiator")
        t.start()

    def _negotiation_loop(self):
        while not self._stop_flag.is_set():
            for host_id in range(1, 7):
                requests_batch = registry.drain_host_inbox(host_id)
                for req in requests_batch:
                    self._handle_request(host_id, req)
            time.sleep(0.5)  # tight loop — no race with daemon threads

    def _handle_request(self, host_id: int, req: HostingRequest):
        daemon_id = req.daemon_id
        domain    = req.domain
        kid       = req.kid
        persona   = HOST_PERSONAS[host_id - 1]

        _log(
            f"Incoming hosting request from Daemon {daemon_id} for '{domain}'.",
            source=f"CDN-Host-{host_id}"
        )

        currently_hosting = len(self._hosted[host_id])

        if currently_hosting >= HOST_CAPACITY:
            # Full — Ollama generates a polite rejection reason
            system = (
                f"You are a web hosting provider ({persona}). "
                f"A user wants to host their domain '{domain}' on your server, "
                f"but you are at full capacity ({HOST_CAPACITY}/{HOST_CAPACITY} sites). "
                "Output JSON with key 'rejection_reason' (one friendly sentence)."
            )
            data   = ollama_client.query(system, "Compose your rejection message.", ["rejection_reason"])
            reason = data["rejection_reason"] if data else "Capacity full."

            registry.set_host_state(host_id, HostState.FULL)
            _log(f"REJECTED '{domain}' (full). Reason: {reason}", source=f"CDN-Host-{host_id}")
            registry.deliver_response(daemon_id, HostingRejected(host_id=host_id, reason=reason))
            return

        # Accept — create website content, register, respond
        self._hosted[host_id].append(domain)
        registry.host_capacities[host_id] = len(self._hosted[host_id])

        # Ollama writes a welcome message for this domain
        system = (
            f"You are a web hosting provider ({persona}). "
            f"You are about to host the decentralized website '{domain}' for a new customer "
            f"whose identity is {kid[:20]}... "
            "Write a short, friendly HTML welcome page (2-3 sentences). "
            "Output JSON with key 'html_body' (the inner HTML content only, no tags wrapping)."
        )
        data     = ollama_client.query(system, "Write the welcome page content.", ["html_body"])
        html_body = (
            data["html_body"] if data
            else f"Welcome to {domain}. Hosted by Kinetic Host #{host_id}. Owner KID: {kid}."
        )
        html = (
            f"<!DOCTYPE html><html><head><title>{domain}</title></head>"
            f"<body><h1>Welcome to {domain}</h1><p>{html_body}</p>"
            f"<footer><small>Served by Kinetic Host #{host_id} | Owner: {kid}</small></footer>"
            f"</body></html>"
        )

        _exec("host", host_id, ["mkdir", "-p", f"/var/www/{domain}"])
        # Write the HTML file inside the container
        import subprocess
        subprocess.run(
            ["sudo", "podman", "exec", "-i", f"clab-kinetic-swarm-host{host_id}", "sh", "-c", f"cat > /var/www/{domain}/index.html"],
            input=html.encode('utf-8')
        )

        peer_id = registry.host_peer_ids.get(host_id, "UNKNOWN")
        capacity_str = f"{len(self._hosted[host_id])}/{HOST_CAPACITY}"

        _log(
            f"ACCEPTED '{domain}'. Website scaffolded. Capacity: {capacity_str}. "
            f"Sending PeerID to Daemon {daemon_id}.",
            source=f"CDN-Host-{host_id}"
        )
        if len(self._hosted[host_id]) >= HOST_CAPACITY:
            registry.set_host_state(host_id, HostState.FULL)

        registry.deliver_response(
            daemon_id,
            HostingAccepted(host_peer_id=peer_id, host_id=host_id)
        )

    # ── Narrative loop ───────────────────────────────────────────────────

    def start_narrative(self):
        t = threading.Thread(target=self._narrative_loop, daemon=True, name="HostNarrative")
        t.start()

    def _narrative_loop(self):
        while not self._stop_flag.is_set():
            idx     = random.randint(1, 6)
            persona = HOST_PERSONAS[idx - 1]
            domains = self._hosted.get(idx, [])
            state   = registry.host_states.get(idx, HostState.BOOTING)

            if state not in (HostState.READY, HostState.FULL):
                time.sleep(15)
                continue

            system = (
                f"You are a CDN web host ({persona}) running Kinetic Host #{idx}. "
                f"You are currently hosting {len(domains)} websites: "
                f"{', '.join(domains[:3]) or 'none yet'}{'...' if len(domains) > 3 else ''}. "
                "Output JSON with keys: "
                "'traffic_status' (e.g. 'Routing requests for user5.kin') "
                "and 'log' (one technical sentence about current activity)."
            )
            data = ollama_client.query(system, "Report your server status.", ["traffic_status", "log"])
            if data:
                status = data["traffic_status"]
                log    = data["log"]
                _log(
                    f"[{status}] {log} ({len(domains)}/{HOST_CAPACITY} sites)",
                    source=f"CDN-Host-{idx}"
                )

            time.sleep(random.uniform(25, 55))

    def stop(self):
        self._stop_flag.set()
