# kinetic-pac

## 1. Overview
`kinetic-pac` is a dangerous, highly privileged daemon and CLI tool that manages OS-level Proxy Auto-Configuration (PAC). It hijacks the host operating system's networking environment, forcing standard web browsers (Chrome, Firefox, Safari) to seamlessly route `.kin` domains to the Kinetic node without breaking normal internet access.

## 2. Usage & Integration
This crate produces a standalone executable. Because it mutates global OS state, it is typically installed as an elevated system service.

```bash
# Start the PAC server and aggressively inject it into the OS settings
kinetic-pac start

# Stop the server and execute the fail-safe restoration sequence
kinetic-pac stop
```

## 3. Internal Architecture & The Threat Model
Because this tool intercepts all web traffic at the OS level, a failure to clean up could permanently break the user's internet. To mitigate this, `kinetic-pac` performs extremely aggressive state management:
*   **Snapshotting:** Before touching any settings, it scrapes all existing proxy configurations across all network adapters and serializes the exact environment to a strict `proxy_active.lock` file.
*   **OS Injection (`src/os/*`):** 
    *   **Windows:** Executes PowerShell to modify `WinINet` registry keys (`HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings`).
    *   **macOS:** Enumerates all active Wi-Fi, Ethernet, and VPN adapters and issues individual `networksetup -setautoproxyurl` commands.
    *   **Linux:** Switches between `gsettings` (GNOME D-Bus) and `kwriteconfig5` (KDE Plasma) to modify `ProxyType` globally.
*   **Safe Restoration & Merging:** When stopping, it reads the lock file to perfectly revert the OS proxy settings. If the user already had a corporate PAC script active, `kinetic-pac` merges the Javascript ASTs, injecting the `.kin` routing table while preserving the original proxy logic for all other domains.

## 4. Reading Guide
To fully understand this crate, we recommend reading it in the following order:

### Prerequisites
* None. This is a standalone infrastructural utility.

### File Traversal (Leaf-First)
Read this crate in the following order:
1. `src/os/windows.rs`, `macos.rs`, `linux.rs` - Start here to understand exactly how the crate executes system-level mutations to the host OS.
2. `src/main.rs` - Read the `build_pac_script()` function to see how the proxy Javascript is dynamically constructed (and safely merged with pre-existing scripts), followed by the `axum` HTTP server initialization.

## 5. Taxonomy & Links
* **Taxonomy:** This crate belongs to Layer 5. Please read [`./LAYER_5.md`](./LAYER_5.md) to understand the strict architectural constraints of this layer.
* **Repository:** [https://github.com/saifmukhtar/kinetic](https://github.com/saifmukhtar/kinetic)
