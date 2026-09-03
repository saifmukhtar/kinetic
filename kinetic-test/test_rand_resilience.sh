#!/bin/bash
cargo build -p kinetic-daemon
echo "Starting daemon in background..."
../target/debug/kinetic-daemon > daemon.log 2>&1 &
DAEMON_PID=$!

cleanup() {
    echo "=== Cleaning up ==="
    kill $DAEMON_PID 2>/dev/null || true
    sudo iptables -D OUTPUT -p tcp --dport 443 -d api.rand.sh -j REJECT 2>/dev/null || true
    sudo iptables -D OUTPUT -p tcp --dport 443 -d rand.cloudflare.com -j REJECT 2>/dev/null || true
    sudo iptables -D OUTPUT -p tcp --dport 443 -d api2.rand.sh -j REJECT 2>/dev/null || true
    sudo iptables -D OUTPUT -p tcp --dport 443 -d api3.rand.sh -j REJECT 2>/dev/null || true
}
trap cleanup EXIT

sleep 10
echo "=== Initial Startup Logs ==="
grep -i "rand" daemon.log

echo "=== Blocking Rand IPs via iptables ==="
sudo iptables -A OUTPUT -p tcp --dport 443 -d api.rand.sh -j REJECT
sudo iptables -A OUTPUT -p tcp --dport 443 -d rand.cloudflare.com -j REJECT
sudo iptables -A OUTPUT -p tcp --dport 443 -d api2.rand.sh -j REJECT
sudo iptables -A OUTPUT -p tcp --dport 443 -d api3.rand.sh -j REJECT

echo "Waiting 65 seconds for next heartbeat tick..."
sleep 65

echo "=== Logs during block ==="
grep -i "Heartbeat loop: Rand kyn unavailable" daemon.log || grep -i "Heartbeat using cached" daemon.log || grep -i "unreachable" daemon.log

echo "=== Unblocking Rand IPs ==="
sudo iptables -D OUTPUT -p tcp --dport 443 -d api.rand.sh -j REJECT 2>/dev/null || true
sudo iptables -D OUTPUT -p tcp --dport 443 -d rand.cloudflare.com -j REJECT 2>/dev/null || true
sudo iptables -D OUTPUT -p tcp --dport 443 -d api2.rand.sh -j REJECT 2>/dev/null || true
sudo iptables -D OUTPUT -p tcp --dport 443 -d api3.rand.sh -j REJECT 2>/dev/null || true



echo "Waiting 65 seconds for recovery..."
sleep 65

echo "=== Logs after recovery ==="
tail -n 20 daemon.log | grep -i "rand"

