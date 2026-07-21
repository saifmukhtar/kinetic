#!/bin/bash
# run_all_fuzzers.sh
# Discovers all cargo-fuzz targets in the workspace and runs them sequentially.

set -e

# Default to 3600 seconds (1 hour) per target if not specified.
DURATION=${1:-3600}

echo "=========================================================="
echo "🛡️  Kinetic Fuzzing Automation Runner 🛡️"
echo "=========================================================="
echo "Run duration per target: ${DURATION} seconds"

# Ensure cargo-fuzz is installed
if ! command -v cargo-fuzz &> /dev/null; then
    echo "Installing cargo-fuzz..."
    cargo install cargo-fuzz
fi

# Switch to nightly since cargo-fuzz requires it
export RUSTUP_TOOLCHAIN=nightly

# Find all fuzz directories
FUZZ_DIRS=$(find . -name "fuzz" -type d | sort)
TOTAL_CRASHES=0
declare -a CRASHED_TARGETS

for DIR in $FUZZ_DIRS; do
    if [ ! -f "$DIR/Cargo.toml" ]; then
        continue
    fi
    
    CRATE_DIR=$(dirname "$DIR")
    echo "----------------------------------------------------------"
    echo "🔍 Analyzing crate: $CRATE_DIR"
    
    cd "$CRATE_DIR"
    
    # List all fuzz targets in this crate
    TARGETS=$(cargo +nightly fuzz list 2>/dev/null) || true
    
    for TARGET in $TARGETS; do
        echo "🚀 Running fuzz target: $TARGET in $CRATE_DIR for ${DURATION}s"
        
        # Run cargo fuzz. We don't want it to exit the script if it crashes, 
        # so we catch the exit code.
        set +e
        cargo +nightly fuzz run "$TARGET" -- -max_total_time="$DURATION"
        EXIT_CODE=$?
        set -e
        
        if [ $EXIT_CODE -ne 0 ]; then
            echo "❌ CRASH DETECTED in $TARGET!"
            TOTAL_CRASHES=$((TOTAL_CRASHES + 1))
            CRASHED_TARGETS+=("$CRATE_DIR/$TARGET")
        else
            echo "✅ Target $TARGET finished successfully without crashes."
        fi
    done
    
    cd - > /dev/null
done

echo "=========================================================="
echo "🏁 Fuzzing Run Complete! 🏁"
echo "Total crashes found: $TOTAL_CRASHES"

if [ $TOTAL_CRASHES -gt 0 ]; then
    echo "The following targets experienced crashes/hangs:"
    for CRASH in "${CRASHED_TARGETS[@]}"; do
        echo " - $CRASH"
    done
    echo "Check the 'fuzz/artifacts' directory in each crate for crash inputs!"
    exit 1
fi

echo "All fuzz targets passed with flying colors."
exit 0
