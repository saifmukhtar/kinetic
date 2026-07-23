# Tauri Desktop App

The **Kinetic Desktop** app (built with Tauri) is the easiest way to get started. It gives you a graphical control panel for everything the daemon does — registering names, managing DNS records, checking network status — without ever opening a terminal.

## Download

Download from [kinetic.saifmukhtar.dev/download](https://kinetic.saifmukhtar.dev/download):

| OS | File |
|---|---|
| Linux | `.AppImage` |
| macOS | `.dmg` |
| Windows | `.exe` (installer) |

## Installation

### Linux

```bash
chmod +x kinetic-desktop.AppImage
./kinetic-desktop.AppImage
```

Or move it to `/usr/local/bin/` to launch from anywhere.

### macOS

Open the `.dmg`, drag **Kinetic Desktop** to your Applications folder. On first launch, macOS may show a security prompt — go to **System Settings → Privacy & Security → Allow Anyway**.

### Windows

Run the `.exe` installer and follow the prompts. It installs Kinetic Desktop and optionally adds it to your Start Menu.

---

## First launch

When you open the app for the first time, it checks whether the Kinetic daemon is running on your machine.

If the daemon **is not installed yet**, go to the **Engine** section (sidebar → Engine) and choose an installation profile:

| Profile | Installs | What it does |
|---|---|---|
| **Complete Setup (Recommended)** | Daemon + CLI + DNS Server | Installs everything and configures your OS to resolve `.kin` names natively |
| **Minimal Setup** | Daemon + CLI | Installs the daemon only — no OS DNS changes. Best for corporate VPNs or restricted networks |

Click **Install** and accept the administrator/root permission prompt. The app uses:
- **Linux**: `pkexec` (PolicyKit)
- **macOS**: `osascript` with administrator privileges
- **Windows**: `PowerShell` UAC elevation

Installation downloads binaries from [GitHub Releases](https://github.com/saifmukhtar/kinetic/releases/latest) and verifies their checksums.

---

## The interface

The app has a sidebar with 7 sections:

### Overview

Your live network dashboard:

- **Peers** — how many DHT neighbors your daemon sees
- **DHT Size** — number of records in the distributed table
- **Uptime** — how long the daemon has been running
- **NAT Status** — whether your daemon is reachable from the internet
- **Drand Pulse** — the current randomness round (used by the VDF)
- **Names** — number of `.kin` names you own locally

The overview auto-refreshes every 7 seconds. You can also hit the **Refresh** button manually.

### Identity

Manage your cryptographic identity — the 24-word seed phrase that controls all your names.

**Generate a new identity:**
1. Click **Generate Master Seed**
2. Your 24-word seed phrase appears — write every word down, in order
3. Tick the confirmation checkbox
4. Click **Save & Initialize Identity**

::: danger One chance to write it down
The seed is generated fresh each time you click Generate. Once you save it, the phrase is never shown again. There is no "show my seed" button. Write it down before clicking Save.
:::

**Restore from an existing seed:**
If you already have a 24-word phrase (e.g. from a previous install), paste it into the **Restore Identity** panel and click **Restore & Restart**. The daemon restarts and picks up the restored identity.

### Names

Manage the DNS records for your registered `.kin` names.

1. Select a name from the dropdown (your owned names are listed automatically)
2. Add, edit, or remove DNS records in the table
3. Click **Save Draft** to write changes to local storage only
4. Click **Save & Publish** to sign and push the updated zone to the DHT network

Publishing makes your records visible to anyone resolving your name. Until you publish, changes are local only.

To register a new name, enter it in the **Register** field and click **Register**. A progress bar shows VDF computation status in real time via server-sent events.

To renew an existing name, select it and click **Renew**.

### Mempool

Shows active VDF computation tasks — their current phase, progress percentage, and iteration count. If a task fails, the error message appears here.

### Resolver

Test any `.kin` name. Type it in the search box and click **Resolve**. The raw result from the DHT is shown as JSON — useful for debugging whether a name is live and what it contains.

### Engine

Install or reinstall the system components (daemon, DNS server). Also shows the current installation state. Use **Clean Install** to wipe and reinstall from scratch.

::: warning Clean install removes data
The Clean Install option deletes the existing data directory including your identity key. Back up your 24-word seed before using it.
:::

### Preferences

- **Theme** — Adaptive (follows OS), Dark, or Light
- **Launch on startup** — toggle auto-start with your OS session

---

## System tray

The app lives in the system tray after you close the window. Right-click the tray icon to:

- **Show Kinetic** — bring the window back
- **Hide Window** — minimize to tray
- **Quit Kinetic** — exit the app completely

Left-click or double-click the tray icon to show the window.

---

## Where is my data?

The desktop app uses the same data directory as the CLI:

| OS | Path |
|---|---|
| Linux | `~/.local/share/kinetic/` |
| macOS | `~/Library/Application Support/kinetic/` |
| Windows | `%LOCALAPPDATA%\kinetic\` |

The API token is read directly from `api.token` in that directory — you don't need to handle authentication manually.

---

## The daemon must be running

The app is a **control panel** for the daemon — it does not run the daemon itself. If the daemon is not installed or stopped, the sidebar shows "Daemon offline" and most functions are unavailable.

To start the daemon after installing it through the Engine section, it runs as a system service automatically. If you need to start it manually:

```bash
# Linux / macOS
sudo kinetic-daemon start-service

# Windows (PowerShell as Admin)
kinetic-daemon.exe start-service
```
