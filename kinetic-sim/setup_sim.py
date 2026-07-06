#!/usr/bin/env python3
"""
setup_sim.py — Pre-flight setup for the Kinetic simulation.

Generates:
  - Static Ed25519 network keypairs for all 10 nodes
  - Per-container config.toml (bootstrap nodes, ports, storage paths)
  - topology.clab.yml for ContainerLab + Podman

After running this script:
  sudo containerlab deploy -t topology.clab.yml
  python3 orchestrator.py
"""

import os
import subprocess
import sys
import shutil

try:
    import toml
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "toml"])
    import toml

try:
    import yaml
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml"])
    import yaml

SIM_DIR  = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SIM_DIR, "sim-data")
ROOT_DIR = os.path.dirname(SIM_DIR)  # kinetic/ workspace root

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Build simulation binaries
# ─────────────────────────────────────────────────────────────────────────────

def build_binaries():
    print("=" * 60)
    print("Building kinetic binaries with --features simulation ...")
    print("(This forces VDF iterations=1000 and skips S/Kademlia PoW)")
    print("=" * 60)

    packages = [
        "kinetic-daemon",
        "kinetic-node",
        "kinetic-host",
        "kinetic-cli",
    ]
    cmd = [
        "cargo", "build", "--release",
        "--features", "simulation",
    ] + [arg for pkg in packages for arg in ("-p", pkg)]

    result = subprocess.run(cmd, cwd=ROOT_DIR)
    if result.returncode != 0:
        print("ERROR: Cargo build failed. Check errors above.")
        sys.exit(1)
    print("Build complete.\n")


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Generate static network keys for all 10 nodes
# ─────────────────────────────────────────────────────────────────────────────

def generate_static_keys() -> list[str]:
    print("Generating static Ed25519 keypairs for 10 nodes...")
    keygen_dir = os.path.join(SIM_DIR, "keygen")
    keygen_bin = os.path.join(keygen_dir, "target", "release", "keygen")

    if not os.path.exists(keygen_bin):
        print("Building keygen tool...")
        subprocess.check_call(["cargo", "build", "--release"], cwd=keygen_dir)

    peer_ids = []
    for i in range(1, 11):
        node_dir = os.path.join(DATA_DIR, f"node{i}")
        os.makedirs(node_dir, exist_ok=True)
        key_path = os.path.join(node_dir, "static_network_key.bin")

        result = subprocess.run([keygen_bin, key_path], capture_output=True, text=True)
        peer_id = result.stdout.strip()
        peer_ids.append(peer_id)
        print(f"  Node {i:2d}: {peer_id[:40]}...")

    print(f"Generated {len(peer_ids)} node keypairs.\n")
    return peer_ids


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Write per-container config.toml
# ─────────────────────────────────────────────────────────────────────────────

def generate_configs(peer_ids: list[str]):
    print("Writing per-container config.toml files...")

    bootstrap_nodes = [
        f"/ip4/172.21.10.{i}/tcp/6071/p2p/{peer_ids[i-1]}"
        for i in range(1, 11)
    ]

    for role, count, ip_prefix in [
        ("node",   10, "172.21.10"),
        ("daemon", 34, "172.21.20"),
        ("host",    6, "172.21.30"),
    ]:
        for i in range(1, count + 1):
            container_dir = os.path.join(DATA_DIR, f"{role}{i}")
            os.makedirs(container_dir, exist_ok=True)

            config = {
                "network": {
                    "bootstrap_nodes": bootstrap_nodes,
                    "enable_mdns": False,
                },
                "daemon": {
                    "storage_dir": "/root/.config/kinetic/db",
                },
            }

            with open(os.path.join(container_dir, "config.toml"), "w") as f:
                toml.dump(config, f)

    print(f"Config files written to sim-data/.\n")


# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Write topology.clab.yml
# ─────────────────────────────────────────────────────────────────────────────

def generate_topology():
    print("Generating topology.clab.yml...")

    bin_dir    = os.path.join(ROOT_DIR, "target", "release")
    shared_vol = os.path.join(SIM_DIR, "kinetic-shared")

    topology = {
        "name": "kinetic-swarm",
        "mgmt": {
            "network":     "kinetic-net",
            "ipv4-subnet": "172.21.0.0/16",
        },
        "topology": {
            "nodes": {}
        },
    }
    nodes = topology["topology"]["nodes"]

    def _binds(role: str, idx: int) -> list[str]:
        return [
            f"{DATA_DIR}/{role}{idx}:/sim-data",
            f"{SIM_DIR}/entrypoint.sh:/entrypoint.sh",
            f"{bin_dir}/kinetic-daemon:/usr/local/bin/kinetic-daemon",
            f"{bin_dir}/kinetic-node:/usr/local/bin/kinetic-node",
            f"{bin_dir}/kinetic-host:/usr/local/bin/kinetic-host",
            f"{bin_dir}/kinetic-cli:/usr/local/bin/kinetic-cli",
            f"{shared_vol}:/shared-volume",
        ]

    for i in range(1, 11):
        nodes[f"node{i}"] = {
            "kind":       "linux",
            "image":      "localhost/kinetic-base:latest",
            "mgmt-ipv4":  f"172.21.10.{i}",
            "binds":      _binds("node", i),
            "cmd":        f"bash /entrypoint.sh node {i}",
        }

    for i in range(1, 35):
        nodes[f"daemon{i}"] = {
            "kind":       "linux",
            "image":      "localhost/kinetic-base:latest",
            "mgmt-ipv4":  f"172.21.20.{i}",
            "binds":      _binds("daemon", i),
            "cmd":        f"bash /entrypoint.sh daemon {i}",
        }

    for i in range(1, 7):
        nodes[f"host{i}"] = {
            "kind":       "linux",
            "image":      "localhost/kinetic-base:latest",
            "mgmt-ipv4":  f"172.21.30.{i}",
            "binds":      _binds("host", i),
            "cmd":        f"bash /entrypoint.sh host {i}",
        }

    with open(os.path.join(SIM_DIR, "topology.clab.yml"), "w") as f:
        yaml.dump(topology, f, default_flow_style=False, sort_keys=False)

    print(f"topology.clab.yml written ({len(nodes)} containers).\n")


# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Install Python deps for orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def install_python_deps():
    print("Installing Python orchestrator dependencies...")
    deps = ["flask", "flask-cors", "requests", "toml", "pyyaml"]
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet"] + deps)
    print("Python deps installed.\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Clean old sim data
    if os.path.exists(DATA_DIR):
        print(f"Cleaning old sim-data/ ...")
        shutil.rmtree(DATA_DIR)

    shared_vol = os.path.join(SIM_DIR, "kinetic-shared")
    shutil.rmtree(shared_vol, ignore_errors=True)
    os.makedirs(DATA_DIR,    exist_ok=True)
    os.makedirs(shared_vol,  exist_ok=True)

    install_python_deps()
    build_binaries()
    peer_ids = generate_static_keys()
    generate_configs(peer_ids)
    generate_topology()

    print("=" * 60)
    print("Setup complete! Next steps:")
    print()
    print("  1. Build container image (if not done):")
    print("       podman build -t localhost/kinetic-base:latest -f Containerfile .")
    print()
    print("  2. Deploy the ContainerLab topology:")
    print("       sudo containerlab deploy -t topology.clab.yml")
    print()
    print("  3. Start Ollama (if not running):")
    print("       ollama serve &")
    print()
    print("  4. Start the causal orchestrator:")
    print("       python3 orchestrator.py")
    print()
    print("  5. Open the dashboard:")
    print("       cd kinetic-dashboard && npm run dev")
    print("=" * 60)
