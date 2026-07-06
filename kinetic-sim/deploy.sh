#!/bin/bash
set -e

echo "Building kinetic-base container image..."
sudo podman build --network host -t kinetic-base:latest -f Containerfile .

echo "Building Kinetic Rust binaries (Release mode)..."
cd ..
cargo build --release --features simulation
cd kinetic-sim

echo "Deploying Containerlab topology via Podman..."
sudo containerlab deploy -t topology.clab.yml --runtime podman

echo ""
echo "Deployment successful! 50 nodes are now running."
echo "You can check the running containers with: podman ps"
echo "To execute a daemon on node 1: podman exec -it clab-kinetic-swarm-daemon1 kinetic-daemon"
echo "To destroy the lab later: sudo containerlab destroy -t topology.clab.yml --runtime podman"
