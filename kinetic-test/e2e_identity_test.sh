#!/bin/bash
set -e

echo "Building Kinetic Workspace..."
pkill -9 kinetic-daemon || true
sleep 1
cargo build -p kinetic-daemon -p kinetic-cli --features kinetic-core/simulation,kinetic-kid/simulation

TEST_DIR="/tmp/kinetic_identity_test"
CONFIG_FILE="$TEST_DIR/config.toml"
DB_DIR="$TEST_DIR/db"

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

cat <<EOF > "$CONFIG_FILE"
[daemon]
api_port = 16005
dns_port = 10055
proxy_port = 5468
storage_dir = "$DB_DIR"

[network]
p2p_port = 16075
bootstrap_nodes = []
EOF

export KINETIC_CONFIG_PATH="$CONFIG_FILE"
export KINETIC_DATA_DIR="$TEST_DIR"

echo "Starting isolated Kinetic Daemon in background..."
../target/debug/kinetic-daemon &
DAEMON_PID=$!
trap "kill $DAEMON_PID 2>/dev/null || true" EXIT

echo "Waiting for Daemon API to become available on port 16005..."
for i in {1..120}; do
    if curl -s http://127.0.0.1:16005/ >/dev/null 2>&1 || [ $? -eq 7 -o $? -eq 52 ]; then
        if bash -c "</dev/tcp/127.0.0.1/16005" 2>/dev/null; then
            echo "Daemon is up!"
            break
        fi
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

echo "Generating new Kinetic Identity (KID)..."
../target/debug/kinetic-cli identity create --output "$TEST_DIR/my-kid.json"

DID=$(grep '"kid"' "$TEST_DIR/my-kid.json" | head -1 | awk -F'"' '{print $4}')
echo "Generated DID: $DID"

echo "Publishing KID to local daemon..."
../target/debug/kinetic-cli identity publish --kid "$TEST_DIR/my-kid.json"

echo "Waiting for propagation..."
sleep 2

echo "Resolving KID directly via Daemon API..."
RESOLVE_OUT=$(curl -s "http://127.0.0.1:16002/resolve-kid/$DID")

echo "Daemon returned: $RESOLVE_OUT"

if echo "$RESOLVE_OUT" | grep -q "$DID"; then
    echo "✅ Identity E2E Test Passed!"
    exit 0
else
    echo "❌ Identity E2E Test Failed!"
    exit 1
fi
