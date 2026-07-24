# Install on Linux

This guide covers installing Kinetic on Linux using the interactive terminal installer.

::: tip Prefer a graphical interface?
Download the **Tauri desktop app** instead — it handles installation for you with a GUI. See the [welcome page](/users/) for the download link.
:::

## Prerequisites

- `curl` installed (standard on all major distros)
- `sudo` access — the installer writes binaries to `/usr/local/bin/` and registers system services
- Port 53 available if you choose the Power User profile (DNS server)

## Run the installer

```bash
curl -sSL https://kinetic.saifmukhtar.dev/install.sh | bash
```

The installer is **interactive**. It presents an arrow-key menu — use `↑` / `↓` to navigate, `Enter` to select.

## Choose your profile

When prompted, pick the profile that fits your use case:

| Profile | Installs | Best for |
|---|---|---|
| **Standard User** | Daemon + CLI | Registering names, resolving `.kin` |
| **Power User** | Daemon + CLI + DNS Server | OS-level `.kin` resolution in your browser |
| **Node Operator** | Node + CLI | Running a P2P infrastructure node |
| **Host Operator** | Host + CLI | Hosting content on a `.kin` address |
| **Custom** | You choose | Mixed setups |

For most users, **Standard User** or **Power User** is the right choice.

::: info What is the DNS Server profile?
The Power User profile installs `kinetic-dns` and configures `systemd-resolved` to forward `.kin` queries to it. This means your browser and all apps on your system can resolve `.kin` names natively without extra configuration.
:::

## What the installer does

1. Downloads binaries from [GitHub Releases](https://github.com/saifmukhtar/kinetic/releases/latest)
2. Verifies SHA256 checksums before installing anything
3. Copies binaries to `/usr/local/bin/`
4. Runs `kinetic setup` to generate your node identity (if no identity exists yet)
5. Installs and starts each service via `systemd`

## Verify the installation

Check the installed versions:

```bash
kinetic --version
```

```bash
kinetic-daemon --version
```

Check that the daemon service is running:

```bash
systemctl status kinetic-daemon
```

You should see `active (running)`.

## First-time setup

The installer runs `kinetic setup` automatically if no identity exists. If you need to re-run it:

```bash
kinetic setup
```

This generates your **24-word seed phrase** — write it down immediately. It is shown once and never again.

::: danger Back up your seed phrase
The seed phrase is shown **once** during setup. If you lose it and lose your machine, you lose your names permanently. Write it down on paper and store it somewhere safe. See [Seed Backup](/users/seed-backup).
:::

## Data directory

Your identity, zones, and API token are stored at:

```
~/.local/share/kinetic/
├── identity.key          # Ed25519 private key — never share this
├── api.token             # Bearer token for the local API (regenerated on restart)
└── zones/
    └── yourname.kin.json # DNS zone file for each registered name
```

## Common issues

### Port 53 already in use

On Ubuntu 22.04+, `systemd-resolved` listens on port 53 by default. The installer handles this automatically for the Power User profile by configuring `resolved.conf.d/kinetic.conf`. If you installed the Standard User profile and later want DNS resolution, upgrade by re-running the installer and selecting Power User.

If you see a conflict manually:

```bash
sudo systemctl disable --now systemd-resolved
```

```bash
sudo systemctl restart kinetic-dns
```

### "Permission denied" on `/usr/local/bin`

The installer requires `sudo`. Run with:

```bash
sudo bash -c "$(curl -sSL https://kinetic.saifmukhtar.dev/install.sh)"
```

### Upgrading

Re-run the installer. It detects an existing installation and offers an upgrade path.

### Full uninstall

Re-run the installer, select **Full Cleanup** when prompted. This removes binaries, services, and data including your identity keys.

::: danger Full cleanup is irreversible
Full cleanup deletes your identity key and all registered name data. Ensure you have your 24-word seed backed up before doing this.
:::
