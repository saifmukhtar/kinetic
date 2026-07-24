# Install on macOS

This guide covers installing Kinetic on macOS using the interactive terminal installer.

::: tip Prefer a graphical interface?
Download the **Tauri desktop app** instead — it handles installation for you with a GUI. See the [welcome page](/users/) for the download link.
:::

## Prerequisites

- `curl` (pre-installed on macOS)
- Administrator password — the installer writes to `/usr/local/bin/` and registers system services
- macOS 12 (Monterey) or later recommended

## Run the installer

Open **Terminal** and run:

```bash
curl -sSL https://kinetic.saifmukhtar.dev/install.sh | bash
```

The installer is **interactive**. Use `↑` / `↓` to navigate, `Enter` to select.

## Choose your profile

| Profile | Installs | Best for |
|---|---|---|
| **Standard User** | Daemon + CLI | Registering names, resolving `.kin` |
| **Power User** | Daemon + CLI + DNS Server | OS-level `.kin` resolution in your browser |
| **Node Operator** | Node + CLI | Running a P2P infrastructure node |
| **Host Operator** | Host + CLI | Hosting content on a `.kin` address |
| **Custom** | You choose | Mixed setups |

## What the installer does

1. Downloads binaries from [GitHub Releases](https://github.com/saifmukhtar/kinetic/releases/latest)
2. Verifies SHA256 checksums before installing
3. Copies binaries to `/usr/local/bin/` and sets permissions
4. Runs `kinetic setup` to generate your node identity (if none exists)
5. Installs services via `launchd` and starts them

::: info Power User DNS on macOS
The Power User profile creates `/etc/resolver/kin` — a macOS resolver stub file that routes all `.kin` queries to `127.0.0.1:53`. This gives your entire system native `.kin` resolution.
:::

## Verify the installation

Check the installed versions:

```bash
kinetic --version
```

```bash
kinetic-daemon --version
```

Check the daemon is running:

```bash
launchctl list | grep kinetic
```

You should see `kinetic-daemon` in the list with a PID.

## First-time setup

The installer runs `kinetic setup` automatically on first install. To run it manually:

```bash
kinetic setup
```

This generates your **24-word seed phrase**. Write it down immediately — it is shown once and never again.

::: danger Back up your seed phrase
Your 24-word seed is the only way to recover your identity and names if you lose your machine. See [Seed Backup](/users/seed-backup).
:::

## Data directory

Your data is stored at:

```
~/Library/Application Support/kinetic/
├── identity.key          # Private key — never share this
├── api.token             # Local API bearer token
└── zones/
    └── yourname.kin.json # DNS zone for each registered name
```

## macOS-specific issues

### "Cannot be opened because the developer cannot be verified"

macOS Gatekeeper may block the binary on first run. Remove the quarantine attribute:

```bash
xattr -c /usr/local/bin/kinetic-daemon
```

```bash
xattr -c /usr/local/bin/kinetic
```

Or allow it in **System Settings → Privacy & Security → Allow Anyway**.

### Network access permission prompt

macOS will ask if Kinetic can accept incoming network connections. Click **Allow**. The daemon needs this for P2P communication.

### Port 53 conflict

If you have another local DNS service running, the DNS server may fail to bind. Check:

```bash
sudo lsof -i :53
```

Stop the conflicting service, then restart kinetic-dns:

```bash
sudo launchctl kickstart -k system/kinetic-dns
```

### Upgrading

Re-run the installer. It detects the existing installation and prompts for an upgrade or cleanup.

### Full uninstall

Re-run the installer and select **Full Cleanup** when prompted. This removes all binaries, services, and data including your identity.

::: warning Full cleanup deletes your identity
Ensure your 24-word seed is backed up before running a full cleanup.
:::
