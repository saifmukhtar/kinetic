#!/usr/bin/env bash
set -e

echo "[+] Starting local test web server on port 8080..."
python3 -m http.server 8080 > /dev/null 2>&1 &
HTTP_PID=$!

echo "[+] Rebuilding kinetic-host..."
cargo build --release -p kinetic-host

echo "[+] Starting local kinetic-host (listening on port 16004 for health, proxying to 8080)..."
KINETIC_HOST_BACKEND_PORT=8080 \
KINETIC_HOST_P2P_PORT=6071 \
KINETIC_KEY_PATH=/tmp/kinetic_host_test_key.bin \
./target/release/kinetic-host > /tmp/kinetic_host_test.log 2>&1 &
HOST_PID=$!

echo "[+] Waiting for kinetic-host to boot and generate its identity..."
sleep 5

# Fetch the Host's static PeerId from its health API
HOST_PEER_ID=$(curl -s http://127.0.0.1:16004/peer_id)
if [ -z "$HOST_PEER_ID" ]; then
    echo "[-] Failed to fetch kinetic-host Peer ID. Check /tmp/kinetic_host_test.log"
    cat /tmp/kinetic_host_test.log
    kill $HTTP_PID $HOST_PID
    exit 1
fi
echo "[+] kinetic-host running with static PeerId: $HOST_PEER_ID"

echo "[+] Updating test.kin zone payload with the new PeerId..."
cat <<EOF > ~/.config/kinetic/zones/test.kin.json
{
  "records": {
    "@": [
      {
        "type": "PeerId",
        "value": "$HOST_PEER_ID"
      }
    ]
  }
}
EOF

echo "[+] Publishing test.kin..."
cargo run -p kinetic-cli -- publish test.kin

echo "[+] Waiting for DHT publication and propagation (10s)..."
sleep 10

echo "[+] Testing HTTP proxy via daemon (port 5463) to test.kin..."
HTTP_RESPONSE=$(curl -s --max-time 10 --proxy http://127.0.0.1:5463 http://test.kin/ -o /dev/null -w "%{http_code}")
if [ "$HTTP_RESPONSE" -eq 200 ]; then
    echo "[+] SUCCESS: test.kin successfully proxied to local web server! (HTTP $HTTP_RESPONSE)"
    kill $HTTP_PID $HOST_PID
    exit 0
else
    echo "[-] FAILED: Received HTTP $HTTP_RESPONSE from proxy."
    echo "[DEBUG] Daemon Proxy logs:"
    systemctl status kinetic-daemon -n 50 -l
    echo "[DEBUG] Kinetic-Host logs:"
    cat /tmp/kinetic_host_test.log
    kill $HTTP_PID $HOST_PID
    exit 1
fi
