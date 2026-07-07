#!/bin/bash
set -e

echo "Building kinetic-wasm..."

cd "$(dirname "$0")/../kinetic-wasm"

# Ensure wasm-pack is installed
if ! command -v wasm-pack &> /dev/null
then
    echo "wasm-pack could not be found. Installing..."
    cargo install wasm-pack
fi

# Build for the web
# --target web generates ES modules that can be imported directly in the browser
# --out-dir places the output in the Chrome extension folder
wasm-pack build --target web --out-dir ../kinetic-client/extension/wasm

echo "Successfully built kinetic-wasm for the Chrome extension."
