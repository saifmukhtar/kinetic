import os
import sys
import json
import queue
import threading
import time
import random

from flask import Flask, jsonify, Response, stream_with_context
from flask_cors import CORS

from sim_state import registry
from agents.node_agent   import NodeAgent
from agents.host_agent   import HostAgent
from agents.daemon_agent import DaemonAgent

# ─────────────────────────────────────────────────────────────────────────────
# SSE broadcaster — pushes state to all connected dashboard clients
# ─────────────────────────────────────────────────────────────────────────────

_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()

def _broadcast(data: dict):
    """Push a snapshot to all connected SSE clients."""
    payload = f"data: {json.dumps(data)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(payload)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)

def _sse_broadcaster_loop():
    """Background thread: broadcast snapshot whenever state changes."""
    prev_snap = None
    while True:
        snap = registry.snapshot()
        if snap != prev_snap:
            _broadcast(snap)
            prev_snap = snap
        time.sleep(0.5)  # 500ms debounce — fast enough to feel real-time

# ─────────────────────────────────────────────────────────────────────────────
# Flask API
# ─────────────────────────────────────────────────────────────────────────────



# ─────────────────────────────────────────────────────────────────────────────
# Flask API — serves the dashboard
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app, origins="*")

@app.route("/stream")
def stream():
    """SSE endpoint — dashboard connects once, receives push updates on every state change."""
    client_q: queue.Queue = queue.Queue(maxsize=20)
    with _sse_lock:
        _sse_clients.append(client_q)

    # Send initial snapshot immediately on connect
    initial = json.dumps(registry.snapshot())
    _log_initial = f"data: {initial}\n\n"

    @stream_with_context
    def generate():
        yield _log_initial
        while True:
            try:
                msg = client_q.get(timeout=30)
                yield msg
            except queue.Empty:
                yield ":keepalive\n\n"  # SSE comment to keep connection alive
            except GeneratorExit:
                with _sse_lock:
                    if client_q in _sse_clients:
                        _sse_clients.remove(client_q)
                return

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )

@app.route("/snapshot")
def get_snapshot():
    """One-shot snapshot — used by dashboard as fallback if SSE fails."""
    return jsonify(registry.snapshot())

@app.route("/health")
def health():
    return jsonify({"status": "ok", "phase": registry.current_phase})

@app.route("/proxy/<int:host_id>/<domain>/<path:filename>")
def proxy_to_container(host_id, domain, filename):
    import subprocess
    from flask import Response
    
    # SECURITY: Prevent Directory Traversal and Shell Injection
    if ".." in domain or ".." in filename:
        return "Invalid path: Directory traversal blocked", 400
    if filename.startswith("/") or domain.startswith("/"):
        return "Invalid path: Absolute paths blocked", 400
        
    import re
    if not re.match(r'^[\w\.-]+$', domain):
        return "Invalid domain characters", 400
    if not re.match(r'^[\w\./-]+$', filename):
        return "Invalid filename characters", 400
        
    container = f"clab-kinetic-swarm-host{host_id}"
    cmd = ["sudo", "podman", "exec", container, "cat", f"/var/www/{domain}/{filename}"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=5)
        if r.returncode == 0:
            mimetype = "text/html"
            if filename.endswith(".css"): mimetype = "text/css"
            elif filename.endswith(".js"): mimetype = "application/javascript"
            return Response(r.stdout, mimetype=mimetype)
        else:
            return f"Error proxying: {r.stderr.decode('utf-8', errors='ignore')}", 502
    except Exception as e:
        return str(e), 500

# ─────────────────────────────────────────────────────────────────────────────
# Simulation phases
# ─────────────────────────────────────────────────────────────────────────────

def run_simulation():
    """
    Master coroutine — runs all 9 phases sequentially.
    Each phase is a blocking call that only returns when its gate condition is met.
    """
    registry.log("orchestrator", "Orchestrator",
                 "═══════════════════════════════════════════════════════════")
    registry.log("orchestrator", "Orchestrator",
                 " KINETIC SWARM INTELLIGENCE — CAUSAL MULTI-AGENT SIM v1 ")
    registry.log("orchestrator", "Orchestrator",
                 "═══════════════════════════════════════════════════════════")
    registry.log("orchestrator", "Orchestrator",
                 "Architecture: 10 nodes → 6 hosts → 34 daemons")
    registry.log("orchestrator", "Orchestrator",
                 "Model: qwen2.5:3b | VDF: 1000 iters (sim build)")

    # ── Create agents ─────────────────────────────────────────────────────
    node_agent   = NodeAgent()
    host_agent   = HostAgent()
    daemon_agent = DaemonAgent()

    # ── Phase 0: Announce ─────────────────────────────────────────────────
    registry.set_phase(0)
    registry.log("orchestrator", "Orchestrator",
                 "ContainerLab topology assumed deployed. Waiting for containers to initialise...")
    time.sleep(5)   # Give containers a moment to start their processes

    # ── Phase 1: Nodes up ─────────────────────────────────────────────────
    registry.set_phase(1)
    registry.log("orchestrator", "Orchestrator",
                 "Phase 1: Waiting for all 10 DHT infrastructure nodes...")
    try:
        node_agent.boot_all(timeout_per_node=300)
    except TimeoutError as e:
        registry.log("orchestrator", "Orchestrator", f"❌ {e}")
        registry.log("orchestrator", "Orchestrator",
                     "Continuing simulation with partial node set...")

    node_agent.start_narrative()
    registry.log("orchestrator", "Orchestrator",
                 "✅ Phase 1 complete. DHT backbone is live. Starting Phase 2...")
    time.sleep(2)

    # ── Phase 2: Hosts up ─────────────────────────────────────────────────
    registry.set_phase(2)
    registry.log("orchestrator", "Orchestrator",
                 "Phase 2: Waiting for all 6 CDN/proxy hosts...")
    try:
        host_agent.boot_all(timeout=300)
    except TimeoutError as e:
        registry.log("orchestrator", "Orchestrator", f"❌ {e}")
        registry.log("orchestrator", "Orchestrator",
                     "Continuing with partial host set...")

    host_agent.start_negotiator()
    host_agent.start_narrative()
    registry.log("orchestrator", "Orchestrator",
                 "✅ Phase 2 complete. Hosting negotiation layer is open. Starting Phase 3...")
    time.sleep(2)

    # ── Phase 3: Daemons up ───────────────────────────────────────────────
    registry.set_phase(3)
    registry.log("orchestrator", "Orchestrator",
                 "Phase 3: Releasing 34 user daemon lifecycle threads...")
    daemon_agent.start_all()

    # Wait until at least half the daemons are past the WAITING_NODES gate
    _wait_until(
        condition=lambda: sum(
            1 for s in registry.daemon_states.values()
            if s.name not in ("WAITING_NODES",)
        ) >= 17,
        description="half of daemons past WAITING_NODES",
        timeout=120,
    )

    registry.log("orchestrator", "Orchestrator",
                 "✅ Phase 3: Daemons are booting. Lifecycle threads active.")

    # ── Phase 4–9: Run concurrently in daemon threads ─────────────────────
    # Phases 4–9 happen inside each daemon's lifecycle thread.
    # The orchestrator just monitors and reports milestones.

    _monitor_loop()


def _wait_until(condition, description: str, timeout: float = 300.0, poll: float = 3.0):
    """Block until condition() returns True or timeout expires."""
    start = time.monotonic()
    while not condition():
        if time.monotonic() - start > timeout:
            registry.log("orchestrator", "Orchestrator",
                         f"⚠️  Timeout waiting for: {description}")
            return
        time.sleep(poll)
    registry.log("orchestrator", "Orchestrator", f"✅ Condition met: {description}")


def _monitor_loop():
    """
    After Phase 3, the orchestrator watches the daemon state transitions
    and advances the phase counter for the dashboard.
    """
    phase_milestones = {
        4:  lambda: any(s.name == "CREATING_KID"     for s in registry.daemon_states.values()),
        5:  lambda: any(s.name == "NEGOTIATING_HOST"  for s in registry.daemon_states.values()),
        6:  lambda: any(s.name == "REGISTERING"       for s in registry.daemon_states.values()),
        7:  lambda: any(s.name == "PUBLISHING"        for s in registry.daemon_states.values()),
        8:  lambda: any(s.name == "VERIFYING_DNS"     for s in registry.daemon_states.values()),
        9:  lambda: any(s.name in ("ALIVE","HEARTBEATING") for s in registry.daemon_states.values()),
    }


    while True:
        current = registry.current_phase
        for phase, check in phase_milestones.items():
            if phase > current and check():
                registry.set_phase(phase)
                current = phase

        # Milestone announcements
        alive = sum(1 for s in registry.daemon_states.values() if s.name in ("ALIVE","HEARTBEATING"))
        dns_ok = sum(1 for v in registry.daemon_dns_ok.values() if v)

        if alive > 0 and alive % 5 == 0 and alive not in getattr(_monitor_loop, "_announced", set()):
            if not hasattr(_monitor_loop, "_announced"):
                _monitor_loop._announced = set()
            _monitor_loop._announced.add(alive)
            registry.log("orchestrator", "Orchestrator",
                         f"🌐 Milestone: {alive}/34 domains live on the Kinetic network! "
                         f"({dns_ok} DNS verified)")

        time.sleep(5)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    registry.log("orchestrator", "Orchestrator",
                 "Starting Flask API on :5000 ...")

    # SSE broadcaster thread
    sse_thread = threading.Thread(
        target=_sse_broadcaster_loop, daemon=True, name="SSEBroadcaster"
    )
    sse_thread.start()

    # Flask in a daemon thread
    api_thread = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False, threaded=True),
        daemon=True,
        name="FlaskAPI",
    )
    api_thread.start()

    # Run simulation in the main thread
    try:
        run_simulation()
    except KeyboardInterrupt:
        registry.log("orchestrator", "Orchestrator", "Shutdown signal received. Goodbye.")
        sys.exit(0)


if __name__ == "__main__":
    main()
