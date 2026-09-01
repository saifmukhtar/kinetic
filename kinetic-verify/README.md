# Kinetic Verify

`kinetic-verify` provides lightweight cryptographic verification logic for the Kinetic Network. 

## Architecture

This crate acts as a stateless verification pipeline. Its core philosophy is to remain completely detached from storage, networking, or consensus logic. 

**Workflow:**
1. It receives pure data structures (like `Reveal` or `AuthorizedManifest`) from the `kinetic-types` crate.
2. It parses and decodes the embedded URL-safe Base64 Post-Quantum Public Keys (`ML-DSA-65`) from the JSON documents into raw bytes.
3. It hands those raw bytes down to the `kinetic-primitives` sandbox to execute the actual cryptographic math.
4. It returns standard results mapping to `thiserror` domain errors.

By isolating the verification flow into its own crate, we ensure that higher-level components (like the P2P networking layer or local node daemon) can verify signatures seamlessly without accidentally coupling themselves to lower-level cryptographic implementations.
