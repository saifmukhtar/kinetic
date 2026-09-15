# Layer 4: Verification & Domain Rules

## 1. The Hook (Taxonomy)
This crate is part of **Layer 4: Verification & Domain Rules** within the Kinetic 9-Layer Taxonomy. It acts as the strict mathematical rules engine for the network.

## 2. The Core Architectural Rule (The Invariant)
This crate dictates the strict consensus and validation rules of the network, but it must perform **zero I/O execution**. It is a `no_std`-compatible validation sandbox. It must never import `tokio`, `std::fs`, `libp2p`, or any external networking libraries.

## 3. The Horizontal Boundary
This crate exclusively owns the mathematical validation logic for network claims, specifically verifying **Sovereign signatures**, delegated identity claims, and Proof of Patience (VDF) claims. 

It explicitly ignores how these payloads are serialized over the wire, how they are retrieved from peers, or how they are persisted to local storage. It only answers one question: *Is this data cryptographically valid?*

## 4. Why This Exists (Abstraction Defense)
By isolating consensus validation from network and disk I/O, the network's core trust assumptions remain mathematically pure, heavily testable, and completely decoupled from implementation details like databases or P2P libraries. This allows the validation logic to be easily compiled to WebAssembly (Wasm) or embedded in highly constrained environments without dragging in heavy async runtimes.
