#!/bin/bash
echo "Starting daemon in background..."
./target/debug/kinetic-daemon > daemon.log 2>&1 &
DAEMON_PID=$!

sleep 10
echo "=== Initial Startup Logs ==="
grep -i "drand" daemon.log

echo "=== Blocking Drand IPs via iptables ==="
sudo iptables -A OUTPUT -p tcp --dport 443 -d api.drand.sh -j REJECT
sudo iptables -A OUTPUT -p tcp --dport 443 -d drand.cloudflare.com -j REJECT
sudo iptables -A OUTPUT -p tcp --dport 443 -d api2.drand.sh -j REJECT
sudo iptables -A OUTPUT -p tcp --dport 443 -d api3.drand.sh -j REJECT

echo "Waiting 65 seconds for next heartbeat tick..."
sleep 65

echo "=== Logs during block ==="
grep -i "Heartbeat loop: Drand pulse unavailable" daemon.log || grep -i "Heartbeat using cached" daemon.log || grep -i "unreachable" daemon.log

echo "=== Unblocking Drand IPs ==="
sudo iptables -D OUTPUT -p tcp --dport 443 -d api.drand.sh -j REJECT
sudo iptables -D OUTPUT -p tcp --dport 443 -d drand.cloudflare.com -j REJECT
sudo iptables -D OUTPUT -p tcp --dport 443 -d api2.drand.sh -j REJECT
sudo iptables -D OUTPUT -p tcp --dport 443 -d api3.drand.sh -j REJECT

echo "Waiting 65 seconds for recovery..."
sleep 65

echo "=== Logs after recovery ==="
tail -n 20 daemon.log | grep -i "drand"

kill $DAEMON_PID
