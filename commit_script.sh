#!/bin/bash
git add kinetic-verify Cargo.toml Cargo.lock
git commit -m "extracted kinetic-verify crate"

git add kinetic-core/Cargo.toml kinetic-core/src/types/vdf.rs kinetic-core/src/constants.rs
git commit -m "decoupled verification from core"

git add kinetic-network kinetic-cli kinetic-daemon kinetic-dns kinetic-test kinetic-wasm
git commit -m "applied dynamic network ID to verifiers globally"

git add kinetic-core/src/governance kinetic-core/src/api_error.rs kinetic-core/src/error/governance.rs
git commit -m "refactored governance engine"

git add kinetic-core/src/updater.rs kinetic-core/src/error/updater.rs kinetic-core/src/error.rs
git commit -m "removed insecure updater module"

git add kinetic-core/tests kinetic-core/src/traits.rs kinetic-core/src/lib.rs
git commit -m "updated core tests and traits"

git add kinetic-host kinetic-keygen kinetic-pac
git commit -m "updated host, keygen, and pac logic"

git add docs .github whitepaper openapi.yaml
git commit -m "updated docs and CI workflows"

git add -A
git commit -m "cleanup remaining files"
