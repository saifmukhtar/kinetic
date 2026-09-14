# Layer 5: Executables / Application Shell

## 1. The Hook (Taxonomy)
This crate (`kinetic-pac`) belongs to **Layer 5: Executables**. It produces a highly privileged, standalone binary that actively mutates the host operating system's networking environment.

## 2. The Core Architectural Rule (The Invariant)
**Binaries execute configuration and logic; they do not define rules. However, they possess the highest level of destructive system access.**

Unlike Layer 3 (which is pure math), `kinetic-pac` wires together dangerous OS-level system calls (via PowerShell, D-Bus, and `networksetup`) into a deployable application. No other Kinetic crates depend on this crate. 

## 3. The Horizontal Boundary
This crate exclusively owns the OS Proxy Auto-Configuration (PAC) lifecycle and network hijacking.
It explicitly ignores *how* `.kin` domains are resolved by the node. It only cares about writing the correct `proxy.pac` Javascript to intercept OS web requests, forcing the operating system to pass `.kin` traffic down to the local `kinetic-daemon`.

## 4. Why This Exists (Abstraction Defense)
Isolating OS proxy configuration into a separate daemon prevents `kinetic-daemon` from requiring permanent escalated administrative privileges to modify Windows Registries or macOS network configurations. `kinetic-pac` can be installed as a system service once, allowing the main `kinetic-daemon` to run securely in unprivileged userspace while still magically routing browser traffic.
