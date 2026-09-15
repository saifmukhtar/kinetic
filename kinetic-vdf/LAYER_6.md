# Layer 6: Core Infrastructure & Adapters

## 1. The Hook (Taxonomy)
This crate (`kinetic-vdf`) belongs to **Layer 6: Core Infrastructure & Adapters**. It is a concrete infrastructural implementor of abstract rules defined in Layer 5.

## 2. The Core Architectural Rule (The Invariant)
**This crate must depend on `kinetic-core` for its rules, but `kinetic-core` must NEVER depend on this crate.**

As an infrastructure module, `kinetic-vdf` takes the abstract trait `VdfEngine` from `kinetic-core` and writes the actual, heavy execution logic (RSA math and Wesolowski proofs) to satisfy that trait. 

## 3. The Horizontal Boundary
This crate exclusively owns the mathematical execution of Verifiable Delay Functions. 
It explicitly ignores anything unrelated to evaluating or verifying a single VDF proof. It does not know about the network, storage, routing, identity, or actions. 

## 4. Why This Exists (Abstraction Defense)
Isolating the heavy RSA cryptography in Layer 6 prevents the core kernel and other infrastructural components from being weighed down by mathematical dependencies. If Kinetic decides to swap out RSA VDFs for Class Group VDFs or ASIC-based delays in the future, only this single Layer 6 crate needs to be rewritten, leaving the rest of the workspace completely untouched.
