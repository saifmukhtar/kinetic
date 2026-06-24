#!/bin/bash
set -e

echo "Building Kinetic Workspace..."
cargo build

TEST_DIR="/tmp/kinetic_identity_test"
CONFIG_FILE="$TEST_DIR/config.toml"
DB_DIR="$TEST_DIR/db"

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

cat <<EOF > "$CONFIG_FILE"
[daemon]
api_port = 16002
dns_port = 10054
storage_dir = "$DB_DIR"

[network]
p2p_port = 16071
bootstrap_nodes = []
EOF

export KINETIC_CONFIG_PATH="$CONFIG_FILE"

echo "Starting isolated Kinetic Daemon in background..."
./target/debug/kinetic-daemon &
DAEMON_PID=$!

echo "Waiting for Daemon API to become available on port 16002..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:16002/ >/dev/null 2>&1 || [ $? -eq 7 -o $? -eq 52 ]; then
        # Curl returns 52 (Empty reply from server) or 7 (Failed to connect)
        # Actually, let's just check if we can connect at all using bash /dev/tcp
        if bash -c "</dev/tcp/127.0.0.1/16002" 2>/dev/null; then
            echo "Daemon is up!"
            break
        fi
    fi
    sleep 1
done

echo "Generating new Kinetic Identity (KID)..."
./target/debug/kinetic-cli identity create --output "$TEST_DIR/my-kid.json"

DID=$(grep '"kid"' "$TEST_DIR/my-kid.json" | head -1 | awk -F'"' '{print $4}')
echo "Generated DID: $DID"

echo "Publishing KID to local daemon..."
./target/debug/kinetic-cli identity publish-kid "$TEST_DIR/my-kid.json"

echo "Waiting for propagation..."
sleep 2

echo "Resolving KID directly via Daemon API..."
RESOLVE_OUT=$(curl -s "http://127.0.0.1:16002/resolve-kid/$DID")

echo "Daemon returned: $RESOLVE_OUT"

if echo "$RESOLVE_OUT" | grep -q "$DID"; then
    echo "✅ Identity E2E Test Passed!"
    kill $DAEMON_PID
    exit 0
else
    echo "❌ Identity E2E Test Failed!"
    kill $DAEMON_PID
    exit 1
fi
