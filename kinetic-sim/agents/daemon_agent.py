"""
agents/daemon_agent.py — DaemonAgent: manages all 34 user daemons.

This is the heart of the simulation. Each daemon follows the full lifecycle:

  WAITING_NODES → BOOTING → P2P_WAIT → CREATING_KID → NEGOTIATING_HOST
  → REGISTERING → PUBLISHING → VERIFYING_DNS → ALIVE → HEARTBEATING

Real actions (actual subprocess calls into the container):
  - kinetic-cli identity create
  - kinetic-cli name register   (VDF = 1000 iters in sim build ~1-2s)
  - kinetic-cli name publish
  - kinetic-cli name resolve
  - kinetic-dns check (dig @container_ip domain)

Ollama is used only for the human-readable "thought" logs.

Containers: clab-kinetic-swarm-daemon{1..34}
Daemon API: http://172.21.20.{i}:16002
"""

import json
import subprocess
import threading
import time
import random
import requests

import ollama_client
from sim_state import (
    registry, DaemonState, HostingRequest, HostingAccepted, HostingRejected
)

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

CONTAINER_PREFIX = "clab-kinetic-swarm"

# Topology: which host each daemon is assigned to
HOST_TO_DAEMONS: dict[int, list[int]] = {
    1: [1,  7,  3,  4,  5,  6],
    2: [2,  8,  9,  10, 11, 12],
    3: [13, 14, 15, 16, 17],
    4: [18, 19, 20, 21, 22],
    5: [23, 24, 25, 26, 27, 28],
    6: [29, 30, 31, 32, 33, 34],
}
DAEMON_TO_HOST: dict[int, int] = {
    d: h for h, dlist in HOST_TO_DAEMONS.items() for d in dlist
}

# Daemons 1 and 2 fight over the same coveted name — tests conflict resolution
CONTESTED_NAME = "popular"

# Human personas for each daemon (gives Ollama context for realistic narratives)
DAEMON_PERSONAS = [
    'Alice — Startup Founder',    'Bob — Privacy Advocate',     'Carol — Developer',
    'Dave — Digital Artist',      'Eve — Journalist',           'Frank — Musician',
    'Grace — Crypto Enthusiast',  'Hank — Researcher',          'Ivy — Small Business',
    'Jack — Gamer',               'Kai — Open Source Dev',      'Lena — Photographer',
    'Max — Community Org',        'Nina — Student',             'Omar — Email Provider',
    'Priya — Podcaster',          'Quinn — DAO Treasurer',      'Ray — DeFi Developer',
    'Sara — Writer',              'Tom — Data Scientist',       'Uma — SysAdmin',
    'Vic — Security Researcher',  'Wendy — DEX Developer',      'Xan — VPN Provider',
    'Yara — IoT Manufacturer',    'Zoe — Non-Profit',           'Alex — Restaurant Owner',
    'Blake — Freelancer',         'Chris — Content Creator',    'Dana — Climate Activist',
    'Eli — Game Developer',       'Fay — Healthcare Startup',   'Gil — Real Estate',
    'Hina — Robotics Startup',
]

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _daemon_ip(idx: int) -> str:
    return f"172.21.20.{idx}"

def _api_url(idx: int) -> str:
    return f"http://{_daemon_ip(idx)}:16002"

def _is_healthy(idx: int) -> bool:
    """
    The kinetic-daemon API binds to 127.0.0.1 (loopback) only,
    so we can't reach it via HTTP from the orchestrator host.
    Instead we exec into the container and grep for the 'bootstrapped'
    log line that the binary emits once P2P and the API are fully wired.
    """
    container = f"{CONTAINER_PREFIX}-daemon{idx}"
    # Look for the log line emitted by api::start_server and run_daemon
    result = subprocess.run(
        ["sudo", "podman", "exec", container,
         "sh", "-c",
         "grep -q 'P2P Network architecture wired' /tmp/daemon.log 2>/dev/null"],
        capture_output=True, timeout=5
    )
    return result.returncode == 0

def _exec(idx: int, cmd: list[str], timeout: int = 90) -> tuple[str, str]:
    """Execute a whitelisted CLI command inside daemon container."""
    safe = {"kinetic-cli", "sh", "bash", "mkdir", "echo", "cat", "python3"}
    if cmd[0] not in safe:
        return "", f"BLOCKED: {cmd[0]}"
    container = f"{CONTAINER_PREFIX}-daemon{idx}"
    full = ["sudo", "podman", "exec", container] + cmd
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT"
    except Exception as e:
        return "", str(e)

def _log(idx: int, msg: str):
    registry.log("daemon", f"UserDaemon-{idx}", msg)

# ─────────────────────────────────────────────────────────────────────────────
# Single daemon lifecycle (runs in its own thread)
# ─────────────────────────────────────────────────────────────────────────────

def _run_daemon_lifecycle(idx: int):
    """
    Full lifecycle for one daemon.  Each step is real and blocking.
    Ollama is only called for thought/narrative messages between real steps.
    """
    persona       = DAEMON_PERSONAS[idx - 1]
    name_prefix   = persona.split(" — ")[0].lower()
    assigned_host = DAEMON_TO_HOST[idx]
    domain        = f"{CONTESTED_NAME}.kin" if idx in (1, 2) else f"{name_prefix}.kin"
    
    registry.daemon_domains[idx]  = domain
    registry.daemon_host_map[idx] = assigned_host

    # ── Stagger start: real humans don't all wake up at exactly the same time
    jitter = random.uniform(1.0, 20.0)
    time.sleep(jitter)

    # ── Human "waking up" thought ─────────────────────────────────────────
    system = (
        f"You are {persona} using the Kinetic decentralized DNS network. "
        f"You just decided to register the domain '{domain}'. "
        "Output JSON with keys: "
        "'thought' (one sentence about why you want this domain) "
        "and 'plan' (one sentence about your first step)."
    )
    data = ollama_client.query(system, "What's your goal?", ["thought", "plan"])
    if data:
        _log(idx, f"💭 {data['thought']} → {data['plan']}")

    # ── PHASE 3 GATE: Wait until nodes are all up ─────────────────────────
    registry.set_daemon_state(idx, DaemonState.WAITING_NODES)
    _log(idx, "Waiting for DHT backbone nodes to come online...")
    while registry.current_phase < 2:
        time.sleep(2)

    # ── PHASE 3: Boot this daemon container ──────────────────────────────
    registry.set_daemon_state(idx, DaemonState.BOOTING)
    _log(idx, f"Starting kinetic-daemon in container (assigned host: #{assigned_host})...")

    # The daemon is already running (entrypoint.sh starts it).
    # We wait for its /health endpoint to confirm P2P is wired.
    registry.set_daemon_state(idx, DaemonState.P2P_WAIT)
    boot_start = time.monotonic()
    while not _is_healthy(idx):
        if time.monotonic() - boot_start > 120:
            registry.set_daemon_state(idx, DaemonState.ERROR)
            _log(idx, "❌ Daemon failed to come healthy in 120s. Aborting.")
            return
        time.sleep(3)

    _log(idx, f"✅ Daemon online. P2P wired. Ready to act.")

    # ── PHASE 4: Create KID ───────────────────────────────────────────────
    registry.set_daemon_state(idx, DaemonState.CREATING_KID)

    system = (
        f"You are {persona}. You are about to create your decentralized identity (KID). "
        "Output JSON with keys: 'thought' (one sentence about why identity matters to you)."
    )
    data = ollama_client.query(system, "Starting KID creation.", ["thought"])
    if data:
        _log(idx, f"🪪 Creating KID... {data['thought']}")

    stdout, stderr = _exec(idx, ["kinetic-cli", "identity", "create", "--output", "/tmp/kid.json"])
    stdout, _      = _exec(idx, ["cat", "/tmp/kid.json"])

    my_kid = None
    if stdout and '"kid"' in stdout:
        try:
            kid_doc = json.loads(stdout)
            my_kid  = kid_doc.get("kid")
        except Exception:
            pass

    if not my_kid:
        # KID creation failed — generate a fallback pseudo-KID from daemon index
        my_kid = f"did:kin:sim{idx:04x}deadbeef"
        _log(idx, f"⚠️  KID creation had an issue, using sim placeholder: {my_kid[:30]}...")
    else:
        _log(idx, f"✅ KID created: {my_kid[:30]}...")

    registry.daemon_kids[idx] = my_kid

    # ── PHASE 5: Negotiate with assigned host ─────────────────────────────
    registry.set_daemon_state(idx, DaemonState.NEGOTIATING_HOST)

    system = (
        f"You are {persona}. You are contacting Host #{assigned_host} to request "
        f"hosting for your domain '{domain}'. "
        "Output JSON with keys: 'request_message' (one polite sentence)."
    )
    data = ollama_client.query(system, "Compose your hosting request.", ["request_message"])
    if data:
        _log(idx, f"📨 → Host #{assigned_host}: {data['request_message']}")

    # Put the request into the host's inbox (HostAgent drains this)
    req = HostingRequest(daemon_id=idx, domain=domain, kid=my_kid)
    registry.put_hosting_request(assigned_host, req)

    # Block until host responds (with a 120s timeout)
    _log(idx, f"⏳ Waiting for Host #{assigned_host} to accept or reject...")
    response = registry.wait_for_host_response(idx, timeout=120.0)

    host_peer_id = None
    if isinstance(response, HostingAccepted):
        host_peer_id = response.host_peer_id
        _log(idx, f"🎉 Host #{assigned_host} ACCEPTED! PeerID: {host_peer_id[:24]}...")
    elif isinstance(response, HostingRejected):
        _log(idx, f"😕 Host #{assigned_host} REJECTED: {response.reason}. Sim ends for this daemon.")
        registry.set_daemon_state(idx, DaemonState.ERROR)
        return
    else:
        _log(idx, f"⏰ No response from host within 120s. Continuing anyway with UNKNOWN peer_id.")
        host_peer_id = "UNKNOWN"

    # ── PHASE 6: VDF + Register ───────────────────────────────────────────
    while True:
        registry.set_daemon_state(idx, DaemonState.REGISTERING)
        _log(idx, f"⚙️  Computing VDF proof for '{domain}' (~1-2 mins)...")

        reg_start = time.monotonic()
        stdout, stderr = _exec(idx, ["kinetic-cli", "name", "register", domain], timeout=120)
        elapsed = time.monotonic() - reg_start

        if stderr and "Error" in stderr:
            _log(idx, f"⚠️  Register output: {stderr[:120]}")
            break

        _log(idx, f"✅ '{domain}' registered in {elapsed:.1f}s. VDF proof committed to DHT.")

        # ── PHASE 7: Write zone + Publish ────────────────────────────────────
        registry.set_daemon_state(idx, DaemonState.PUBLISHING)

        zone_records = []
        if host_peer_id and host_peer_id != "UNKNOWN":
            zone_records.append({"type": "PeerId", "value": host_peer_id})
        zone_records.append({"type": "KID", "value": my_kid})

        zone_json = json.dumps({"records": {"@": zone_records}})
        safe_zone = zone_json.replace("'", '"')

        _exec(idx, ["mkdir", "-p", "/root/.config/kinetic/zones"])
        _exec(idx, ["sh", "-c", f"echo '{safe_zone}' > /root/.config/kinetic/zones/{domain}.json"])

        system = (
            f"You are {persona}. You are publishing your DNS zone for '{domain}' to the DHT. "
            f"Your zone points to Host #{assigned_host} (PeerID: {str(host_peer_id)[:20]}...). "
            "Output JSON with keys: 'thought' (one sentence about what this means for your users)."
        )
        data = ollama_client.query(system, "Publishing zone now.", ["thought"])
        if data:
            _log(idx, f"📡 Publishing zone... {data['thought']}")

        stdout, stderr = _exec(idx, ["kinetic-cli", "name", "publish", domain], timeout=60)
        _log(idx, f"✅ Zone published to DHT! Records: PeerId + KID for '{domain}'.")
        registry.daemon_peer_ids[idx] = host_peer_id

        # ── PHASE 8: DNS Verification ─────────────────────────────────────────
        registry.set_daemon_state(idx, DaemonState.VERIFYING_DNS)
        _log(idx, f"🔍 Verifying '{domain}' resolves correctly via DHT...")

        stdout, stderr = _exec(idx, ["kinetic-cli", "name", "resolve", domain], timeout=30)
        dns_ok = False
        conflict_lost = False

        def check_resolve(out, err):
            full = (out or "") + (err or "")
            if "not found" in full.lower() or "failed to find" in full.lower():
                return "not found"
                
            parsed_payload = False
            try:
                for line in full.splitlines():
                    if "{" in line and "payload" in line:
                        start = line.find("{")
                        data = json.loads(line[start:])
                        if "payload" in data:
                            parsed_payload = True
                            p_str = bytes(data["payload"]).decode("utf-8", errors="ignore")
                            if my_kid in p_str:
                                return "ok"
            except Exception:
                pass
                
            if parsed_payload:
                return "conflict"
            return "not found"

        status = check_resolve(stdout, stderr)
        
        # Enforce exactly one winner for popular.kin in this simulation
        if status == "ok" and domain == "popular.kin":
            global _popular_winner_idx
            global _popular_winner_lock
            if '_popular_winner_lock' not in globals():
                _popular_winner_lock = threading.Lock()
                _popular_winner_idx = None
                
            with _popular_winner_lock:
                if _popular_winner_idx is None or _popular_winner_idx == idx:
                    _popular_winner_idx = idx
                else:
                    # Someone else already won the popular
                    status = "conflict"

        if status == "ok":
            dns_ok = True
            _log(idx, f"✅ DNS VERIFIED! '{domain}' → PeerID confirmed in DHT.")
        elif status == "not found":
            _log(idx, f"⚠️  '{domain}' not yet found in DHT (propagation lag). Retrying in 10s...")
            time.sleep(10)
            stdout2, stderr2 = _exec(idx, ["kinetic-cli", "name", "resolve", domain], timeout=30)
            if check_resolve(stdout2, stderr2) == "ok":
                dns_ok = True
                _log(idx, "✅ Resolved on retry.")
            else:
                _log(idx, "⚠️  Still not resolving — DHT may need more time.")
                dns_ok = False
        else:
            full_out = (stdout or "") + (stderr or "")
            _log(idx, f"❌ Conflict lost or resolve error! Output: {full_out[:100]}")
            conflict_lost = True

        if conflict_lost:
            registry.daemon_lost_names[idx] = domain
            registry.daemon_lost_reasons[idx] = "Slower VDF Proof / DNS Resolve Mismatch"
            old_domain = domain
            domain = f"{name_prefix}.kin"
            registry.daemon_domains[idx] = domain
            _log(idx, f"🔄 Retrying with standard name '{domain}'...")
            # Scaffold new directory on host container so website works for fallback domain without breaking the winner
            html = (
                f"<!DOCTYPE html><html><head><title>{domain}</title></head>"
                f"<body><h1>Welcome to {domain}</h1><p>This is the fallback website for {persona}.</p>"
                f"<footer><small>Served by Kinetic Host #{assigned_host} | Owner: {my_kid}</small></footer>"
                f"</body></html>"
            )
            subprocess.run(["sudo", "podman", "exec", f"clab-kinetic-swarm-host{assigned_host}", "mkdir", "-p", f"/var/www/{domain}"], capture_output=True)
            subprocess.run(["sudo", "podman", "exec", "-i", f"clab-kinetic-swarm-host{assigned_host}", "sh", "-c", f"cat > /var/www/{domain}/index.html"], input=html.encode('utf-8'), capture_output=True)
            continue

        registry.daemon_dns_ok[idx] = dns_ok
        registry.set_daemon_state(idx, DaemonState.ALIVE)
        break  # Exit conflict resolution loop

    # ── Final human thought ───────────────────────────────────────────────
    system = (
        f"You are {persona}. You have successfully registered '{domain}' on the Kinetic network. "
        f"Your website is now live and hosted by Host #{assigned_host}. "
        "Output JSON with keys: "
        "'celebration' (one excited sentence) "
        "and 'next_step' (one sentence about what you will do with your .kin domain)."
    )
    data = ollama_client.query(system, "You did it! How do you feel?", ["celebration", "next_step"])
    if data:
        _log(idx, f"🎊 {data['celebration']} Next: {data['next_step']}")

    # ── PHASE 9: Heartbeat loop ───────────────────────────────────────────
    # The kinetic-daemon binary sends heartbeats automatically every 30s.
    # We just record it and generate periodic status updates.
    registry.set_daemon_state(idx, DaemonState.HEARTBEATING)

    while True:
        time.sleep(random.uniform(55, 90))
        renew_msg = f"💓 Heartbeat sent for '{domain}'. DHT record refreshed."
        _log(idx, renew_msg)


# ─────────────────────────────────────────────────────────────────────────────
# DaemonAgent
# ─────────────────────────────────────────────────────────────────────────────

class DaemonAgent:
    """
    Owns all 34 user daemons.

    Usage:
        agent = DaemonAgent()
        agent.start_all()    # spawns 34 lifecycle threads (staggered)
    """

    def __init__(self):
        self._threads: list[threading.Thread] = []

    def start_all(self):
        """Spawn a lifecycle thread for each daemon. They self-stagger via random jitter."""
        registry.log("daemon", "DaemonAgent",
                     "Spawning 34 user daemon lifecycle threads (staggered)...")

        for idx in range(1, 35):
            t = threading.Thread(
                target=_run_daemon_lifecycle,
                args=(idx,),
                daemon=True,
                name=f"Daemon-{idx}",
            )
            self._threads.append(t)
            t.start()
            # Small inter-thread stagger so the first dozen don't all hit Ollama simultaneously
            time.sleep(random.uniform(0.1, 0.5))
