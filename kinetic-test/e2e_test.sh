#!/bin/bash
set -e

echo "Building Kinetic Workspace..."
cargo build

TEST_DIR="/tmp/kinetic_test"
CONFIG_FILE="$TEST_DIR/config.toml"
DB_DIR="$TEST_DIR/db"

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

cat <<EOF > "$CONFIG_FILE"
[daemon]
api_port = 16001
dns_port = 10053
storage_dir = "$DB_DIR"

[network]
p2p_port = 16070
bootstrap_nodes = []
EOF

export KINETIC_CONFIG_PATH="$CONFIG_FILE"

echo "Starting isolated Kinetic Daemon in background..."
./target/debug/kinetic-daemon &
DAEMON_PID=$!

# Give it a moment to boot
sleep 2

echo "Registering test name 'e2e.kin'..."
./target/debug/kinetic-cli register e2e.kin 10.0.0.1 --iterations 100

echo "Waiting for propagation..."
sleep 2

echo "Querying DNS loopback on port 10053..."
DIG_OUT=$(dig @127.0.0.1 -p 10053 e2e.kin +short)

echo "DNS returned: $DIG_OUT"

if [ "$DIG_OUT" == "10.0.0.1" ]; then
    echo "✅ E2E Integration Test Passed!"
    kill $DAEMON_PID
    exit 0
else
    echo "❌ E2E Integration Test Failed!"
    kill $DAEMON_PID
    exit 1
fi
