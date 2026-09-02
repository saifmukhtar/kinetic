# kinetic-vdf

A pure Rust implementation of an RSA-based Verifiable Delay Function (VDF) using Wesolowski's proof of exponentiation and Boneh-Bünz-Fisch Blockwise Checkpointing.

## Overview

This crate provides a deterministic, mathematically rigorous VDF engine designed for the Kinetic network. It utilizes hardcoded RSA-2048 moduli and dynamically balances memory overhead with proving speed using blockwise checkpointing.

## Features
- **Wesolowski Proofs**: Highly compressed, fast-verifying VDF proofs.
- **Blockwise Checkpointing**: Limits the Prover's memory usage to ~100MB even at 50,000+ iterations.
- **Fiat-Shamir Prime Generation**: Deterministic, 256-bit prime generation for quotient division using Miller-Rabin primality testing.
- **Deterministic**: Guaranteed to produce bit-identical proofs for consensus across the network.
- **Strict Error Taxonomy**: Implements Kinetic's `VdfError` for robust handling of invalid challenges, truncated proofs, or mathematically unsound operations.
