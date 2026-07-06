#!/bin/bash
set -euo pipefail

echo "Building Kinetic Workspace..."
cargo build -p kinetic-daemon -p kinetic-cli -p kinetic-dns --features kinetic-core/simulation,kinetic-kid/simulation

TEST_DIR="/tmp/kinetic_test"
CONFIG_FILE="$TEST_DIR/config.toml"
DB_DIR="$TEST_DIR/db"

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

cat <<EOF > "$CONFIG_FILE"
[daemon]
api_port = 16006
dns_port = 10056
proxy_port = 5469
storage_dir = "$DB_DIR"

[network]
p2p_port = 16076
bootstrap_nodes = []
EOF

export KINETIC_CONFIG_PATH="$CONFIG_FILE"
export KINETIC_DATA_DIR="$TEST_DIR"

echo "Starting isolated Kinetic Daemon in background..."
../target/debug/kinetic-daemon &
DAEMON_PID=$!
echo "Starting isolated Kinetic DNS in background..."
../target/debug/kinetic-dns-server --api-url http://127.0.0.1:16006 --dns-port 10056 > "$TEST_DIR/dns.log" 2>&1 &
DNS_PID=$!
trap "kill $DAEMON_PID $DNS_PID 2>/dev/null || true" EXIT

echo "Waiting for Daemon API to become available on port 16006..."
for i in {1..120}; do
    if bash -c "</dev/tcp/127.0.0.1/16006" 2>/dev/null; then
        echo "Daemon is up!"
        break
    fi
    sleep 1
done

echo "Waiting for api.token..."
for i in {1..120}; do
    if [ -f "$TEST_DIR/api.token" ]; then
        echo "API token created!"
        break
    fi
    sleep 1
done

echo "Registering test name 'e2e.kin'..."
../target/debug/kinetic-cli name register e2e.kin --iterations 100

echo "Waiting for propagation..."
sleep 2

ZONE_FILE="$TEST_DIR/zones/e2e.kin.json"
if [ -f "$ZONE_FILE" ]; then
    echo "Adding A record to zone file..."
    jq '.records["@"] += [{"type": "A", "value": "10.0.0.1"}]' "$ZONE_FILE" > /tmp/tmp_zone.json && mv /tmp/tmp_zone.json "$ZONE_FILE"
    
    echo "Publishing updated zone file..."
    ../target/debug/kinetic-cli name publish e2e.kin
else
    echo "Zone file not found! Registration failed?"
    exit 1
fi

echo "Waiting for propagation..."
sleep 2

echo "Querying DNS loopback on port 10056..."
DIG_OUT=$(dig @127.0.0.2 -p 10056 e2e.kin +short)

echo "DNS returned: $DIG_OUT"

if [ "$DIG_OUT" == "10.0.0.1" ]; then
    echo "✅ E2E Integration Test Passed!"
    exit 0
else
    echo "❌ E2E Integration Test Failed!"
    exit 1
fi
