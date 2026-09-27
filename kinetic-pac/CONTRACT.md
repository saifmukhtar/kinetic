# Crate Contract: `kinetic-pac`

## 1. Domain Purpose
This is the **OS Proxy Integration** boundary (Layer 6). Its singular role is to cross-platform configure the host operating system to utilize a Proxy Auto-Configuration (PAC) script, ensuring that browsers seamlessly route Web3 `.kin` traffic to the local daemon without requiring manual user browser configuration.

## 2. Pre-conditions (What the caller MUST do)
* **OS Permissions:** The caller MUST execute this tool with sufficient privileges to modify system-level network configurations (e.g., executing `networksetup` on macOS or modifying the Windows Registry).
* **Provide Payload:** The caller MUST provide a valid `pac_url` serving a valid Javascript `.pac` payload. This crate only wires the URL into the OS; it does not serve the file itself.

## 3. Post-conditions & Guarantees (The "Always")
* **State Preservation:** Guarantees that the pre-existing OS proxy configuration is safely serialized to a `pac_router.lock` file *before* applying the new Kinetic proxy, ensuring perfect restoration upon shutdown.
* **Drift Protection:** Guarantees that if a user manually alters their OS proxy settings while the Kinetic daemon is running, the `uninstall()` procedure will detect the drift and refuse to overwrite the user's manual changes with the stale lockfile.
* **Cross-Platform Safety:** Guarantees safe execution of environment-specific commands (`gsettings` for GNOME, `kwriteconfig5` for KDE, `networksetup` for macOS) without panic.

## 4. Anti-Guarantees (The "Never")
* **Zero Network Traffic:** This crate NEVER proxies or touches actual HTTP/TCP traffic. It merely commands the OS where to send it.
* **Zero Consensus/P2P:** This crate NEVER communicates with the P2P swarm, does not understand identities, and does not verify cryptographic signatures.

## 5. Trust Boundaries & Dependencies
* **Internal:** Operates entirely independently of the core Kinetic network math.
* **External:** Fully trusts the host Operating System and Desktop Environment to correctly parse and apply the injected Proxy configuration.
