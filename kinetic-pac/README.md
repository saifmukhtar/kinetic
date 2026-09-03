# kinetic-pac

**The local Proxy Auto-Config (PAC) HTTP server for the Kinetic Network.**

`kinetic-pac` is a specialized, lightweight daemon that serves Proxy Auto-Config (PAC) scripts to your operating system. This allows browsers (like Chrome, Firefox, Safari) and system networking stacks to dynamically route traffic for specific namespaces (like `.kin` domains) directly to your local `kinetic-host` proxy, without tunneling your standard internet traffic.

## Features

- **PAC / WPAD Server**: Hosts a dynamic `proxy.pac` (and `wpad.dat`) file via a local HTTP server powered by `axum`.
- **Zero-Configuration Routing**: Automatically instructs the OS to forward domains ending in your configured namespace (e.g., `.kin`) to your local node, while returning `DIRECT` for all normal internet traffic.
- **OS Native Integration**: Includes a CLI to cleanly modify your host operating system's native proxy settings:
  - **Windows**: Manipulates the Windows Registry to set the `AutoConfigURL`.
  - **macOS**: Uses `networksetup` to set the `autoproxyurl` for the active network interface.
  - **Linux**: Manages GNOME/KDE proxy configurations via `gsettings` or `kwriteconfig5`.
- **Stateful Restorations**: Keeps track of your system's original proxy configuration in a local JSON lockfile before modifying it, ensuring it safely restores your old settings when uninstalled.
- **Background Daemon**: Can be installed and managed as a background system service (`systemd`, `launchd`, `Win32`) via the `service-manager` crate.
