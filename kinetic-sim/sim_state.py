"""
sim_state.py — Shared simulation state registry.

Holds the per-node state machines, the structured log store,
and the typed inboxes that replace the old racy queue polling.
Everything is thread-safe for the Flask API and agent threads.
"""

import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional

# ─────────────────────────────────────────────────────────────────────────────
# State machine enums
# ─────────────────────────────────────────────────────────────────────────────

class NodeState(Enum):
    BOOTING   = auto()
    P2P_WAIT  = auto()
    SYNCED    = auto()
    ROUTING   = auto()
    ERROR     = auto()

class HostState(Enum):
    BOOTING     = auto()
    P2P_WAIT    = auto()
    READY       = auto()
    FULL        = auto()
    ERROR       = auto()

class DaemonState(Enum):
    WAITING_NODES    = auto()
    BOOTING          = auto()
    P2P_WAIT         = auto()
    CREATING_KID     = auto()
    NEGOTIATING_HOST = auto()
    REGISTERING      = auto()
    PUBLISHING       = auto()
    VERIFYING_DNS    = auto()
    ALIVE            = auto()
    HEARTBEATING     = auto()
    ERROR            = auto()

# ─────────────────────────────────────────────────────────────────────────────
# Log entry
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LogEntry:
    id:      int
    time:    str
    source:  str
    message: str
    role:    str  # 'daemon' | 'node' | 'host' | 'orchestrator'
    phase:   Optional[str] = None

# ─────────────────────────────────────────────────────────────────────────────
# Inbox message types between daemon ↔ host agents
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HostingRequest:
    daemon_id:  int
    domain:     str
    kid:        str

@dataclass
class HostingAccepted:
    host_peer_id: str
    host_id:      int

@dataclass
class HostingRejected:
    host_id: int
    reason:  str

# ─────────────────────────────────────────────────────────────────────────────
# Sim Registry — the single source of truth
# ─────────────────────────────────────────────────────────────────────────────

class SimRegistry:
    """Thread-safe shared state for all agents and the Flask API."""

    def __init__(self):
        self._lock = threading.Lock()

        # Phase tracking
        self.current_phase: int = 0
        self.phase_names: Dict[int, str] = {
            0: "Build",
            1: "Nodes Up",
            2: "Hosts Up",
            3: "Daemons Up",
            4: "KID Creation",
            5: "Host Negotiation",
            6: "VDF + Register",
            7: "Zone Publish",
            8: "DNS Verify",
            9: "Heartbeat",
        }

        # Per-entity state machines
        self.node_states:   Dict[int, NodeState]   = {i: NodeState.BOOTING   for i in range(1, 11)}
        self.host_states:   Dict[int, HostState]   = {i: HostState.BOOTING   for i in range(1, 7)}
        self.daemon_states: Dict[int, DaemonState] = {i: DaemonState.WAITING_NODES for i in range(1, 35)}

        # Per-entity metadata
        self.host_peer_ids:      Dict[int, Optional[str]] = {i: None for i in range(1, 7)}
        self.host_capacities:    Dict[int, int]           = {i: 0    for i in range(1, 7)}
        self.daemon_kids:        Dict[int, Optional[str]] = {i: None for i in range(1, 35)}
        self.daemon_domains:     Dict[int, str]           = {}
        self.daemon_host_map:    Dict[int, int]           = {}   # daemon_id → host_id
        self.daemon_peer_ids:    Dict[int, Optional[str]] = {i: None for i in range(1, 35)}
        self.daemon_dns_ok:      Dict[int, bool]          = {i: False for i in range(1, 35)}
        self.daemon_lost_names:  Dict[int, str]           = {}
        self.daemon_lost_reasons:Dict[int, str]           = {}

        # Structured logs (capped at 200 per role)
        self.logs: Dict[str, List[LogEntry]] = {
            "daemon":       [],
            "node":         [],
            "host":         [],
            "orchestrator": [],
        }
        self._log_counter = 0

        # Per-daemon response events — replaces racy queue polling
        # daemon waits on its Event; host sets it and stores the response
        self.daemon_response_events: Dict[int, threading.Event] = {
            i: threading.Event() for i in range(1, 35)
        }
        self.daemon_responses: Dict[int, object] = {}  # HostingAccepted | HostingRejected

        # Host inboxes — HostAgent drains these in its own thread
        self.host_inboxes: Dict[int, "list[HostingRequest]"] = {i: [] for i in range(1, 7)}
        self._inbox_lock = threading.Lock()

    # ── State transitions ─────────────────────────────────────────────────

    def set_node_state(self, idx: int, state: NodeState):
        with self._lock:
            self.node_states[idx] = state

    def set_host_state(self, idx: int, state: HostState):
        with self._lock:
            self.host_states[idx] = state

    def set_daemon_state(self, idx: int, state: DaemonState):
        with self._lock:
            self.daemon_states[idx] = state

    def set_phase(self, phase: int):
        with self._lock:
            self.current_phase = phase
        self.log("orchestrator", "Orchestrator",
                 f"━━━ Phase {phase}: {self.phase_names.get(phase, '?')} ━━━",
                 phase=self.phase_names.get(phase))

    # ── Logging ───────────────────────────────────────────────────────────

    def log(self, role: str, source: str, message: str, phase: str = None):
        with self._lock:
            self._log_counter += 1
            entry = LogEntry(
                id=self._log_counter,
                time=time.strftime("%H:%M:%S"),
                source=source,
                message=message,
                role=role,
                phase=phase,
            )
            bucket = self.logs.get(role, self.logs["orchestrator"])
            bucket.insert(0, entry)
            if len(bucket) > 200:
                bucket.pop()
        # Mirror to stdout for systemd/containerlab log tailing
        print(f"[{time.strftime('%H:%M:%S')}][{role.upper()}][{source}] {message}", flush=True)

    # ── Host peer_id registration ─────────────────────────────────────────

    def register_host_peer_id(self, host_id: int, peer_id: str):
        with self._lock:
            self.host_peer_ids[host_id] = peer_id

    # ── Hosting request / response ────────────────────────────────────────

    def drain_host_inbox(self, host_id: int) -> "list[HostingRequest]":
        """HostAgent calls this to drain all pending requests for a given host."""
        with self._inbox_lock:
            msgs = self.host_inboxes[host_id][:]
            self.host_inboxes[host_id] = []
            return msgs

    def put_hosting_request(self, host_id: int, req: HostingRequest):
        """DaemonAgent calls this to route a request to the correct host inbox."""
        with self._inbox_lock:
            self.host_inboxes[host_id].append(req)

    def deliver_response(self, daemon_id: int, response: object):
        """Host agent calls this to wake up a waiting daemon thread."""
        with self._lock:
            self.daemon_responses[daemon_id] = response
        self.daemon_response_events[daemon_id].set()

    def wait_for_host_response(self, daemon_id: int, timeout: float = 120.0) -> object:
        """Daemon agent blocks here until host delivers a response."""
        fired = self.daemon_response_events[daemon_id].wait(timeout=timeout)
        if not fired:
            return None
        self.daemon_response_events[daemon_id].clear()
        return self.daemon_responses.pop(daemon_id, None)

    # ── Snapshot for API ─────────────────────────────────────────────────

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "phase": self.current_phase,
                "phase_name": self.phase_names.get(self.current_phase, "?"),
                "nodes":   {str(k): {"state": v.name} for k, v in self.node_states.items()},
                "hosts":   {
                    str(k): {
                        "state": v.name,
                        "capacity": self.host_capacities.get(k, 0),
                        "peer_id": self.host_peer_ids.get(k),
                    }
                    for k, v in self.host_states.items()
                },
                "daemons": {
                    str(k): {
                        "state": v.name,
                        "domain": self.daemon_domains.get(k),
                        "kid": self.daemon_kids.get(k),
                        "host": self.daemon_host_map.get(k),
                        "dns_ok": self.daemon_dns_ok.get(k, False),
                        "lost_name": self.daemon_lost_names.get(k),
                        "lost_reason": self.daemon_lost_reasons.get(k),
                    }
                    for k, v in self.daemon_states.items()
                },
                "logs": {
                    role: [
                        {"id": e.id, "time": e.time, "source": e.source,
                         "message": e.message, "type": role}
                        for e in entries
                    ]
                    for role, entries in self.logs.items()
                },
            }


# Module-level singleton — imported by all agents
registry = SimRegistry()
