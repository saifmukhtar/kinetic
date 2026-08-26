# Legacy Chia VDF Engine (Archived)

This branch serves as a standalone, isolated archive for the original `kinetic-vdf` and `kinetic-vdfrs` crates, alongside the C++ `chiavdf` submodule.

## Why was this archived?
The Kinetic project originally relied on the Chia Network's C++ bindings for ClassGroup-based Verifiable Delay Functions (VDFs). However, compiling and maintaining this heavy C++ submodule was an unnecessary burden. 

The entire Kinetic network has since successfully migrated to an RSA-based VDF engine (`kinetic-vdf-rsa`), which is fully implemented in Rust and significantly lighter.

## Contents
* `kinetic-vdf/`: The original Rust bindings wrapping the `chiavdf` C++ engine.
* `kinetic-vdf/chiavdf/`: The Git submodule pointing to the external Chia VDF codebase.
* `kinetic-vdfrs/`: The legacy Rust integration crate for the old VDF.

This branch intentionally contains **only** these legacy crates to keep the `main` branch clean while preserving the old code for historical reference. To view the active Kinetic network code, switch back to the `main` branch.
