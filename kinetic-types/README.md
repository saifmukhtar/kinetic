# Kinetic Types

Core governance primitives, time constants, and post-quantum (ML-DSA-65) serialization logic for the Kinetic Network.

## Architecture

This crate acts as a foundational data-structure layer across the workspace. It enforces the following architectural principles:

- **Mathematical Purity:** It does not interact with disk I/O, networking, or system clocks. 
- **Strict Typing:** Concepts like network time are strictly typed (`Kyn`) to prevent accidental raw integer mutations.
- **Cryptographic Isolation:** All cryptographic hashing (`SHA-256`) and signing (`ML-DSA-65`) logic is delegated down to the isolated `kinetic-primitives` crate.

## Dependencies

This crate uses `serde` and `serde_bytes` for highly optimized binary parsing.
