# Install Kinetic on macOS

This guide will walk you through installing the Kinetic daemon on macOS.

## Prerequisites
- You need Administrator privileges on your Mac, as the Kinetic daemon requires `sudo` to listen on port 53 for DNS resolution.
- Terminal app (or iTerm2).

## Installation Steps

Open your Terminal and run the following command to download and execute the installer:

```bash
curl -sSL https://kinetic.saifmukhtar.dev/install.sh | bash
```

**What this does:**
1. Downloads the latest Kinetic binaries (`kinetic` and `kinetic-daemon`) and installs them to `/usr/local/bin`.
2. Creates the Kinetic data directory at `~/Library/Application Support/kinetic/`.

### 1. Verify the Installation

To verify that the CLI was installed correctly, run:

```bash
kinetic --version
kinetic daemon --help
```

### 2. Start the Daemon

The Kinetic daemon must be run with `sudo` to bind to port 53.

```bash
sudo kinetic daemon
```

Look for the message `"Connected to DHT"` in the output logs.

::: tip
macOS might prompt you with a dialog asking: **"kinetic-daemon would like to receive connections from the network"**. Be sure to click **Allow**.
:::

### 3. Initialize Your Identity

If this is your first time running Kinetic, you need to generate a new identity. Open a **new terminal window** (leaving the daemon running) and run:

```bash
kinetic seed init
```

::: danger
This command generates your master seed phrase. Follow the instructions on the screen to back it up immediately! See the [Seed Backup Guide](/users/seed-backup) for more details.
:::

## Running Automatically (launchd)

To run the Kinetic daemon automatically in the background, you can use macOS `launchd`.

1. Create a file at `~/Library/LaunchAgents/dev.saifmukhtar.kinetic.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.saifmukhtar.kinetic</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/sudo</string>
        <string>/usr/local/bin/kinetic-daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

2. Load the agent:
```bash
launchctl load ~/Library/LaunchAgents/dev.saifmukhtar.kinetic.plist
```

## Common Issues

### "Developer Cannot Be Verified" Error
macOS Gatekeeper may block the binary from running because it was downloaded from the internet. To bypass this, run:
```bash
sudo xattr -cr /usr/local/bin/kinetic
sudo xattr -cr /usr/local/bin/kinetic-daemon
```

### Port 53 Conflicts
If you have other DNS tools installed (like `dnsmasq`), they may conflict with Kinetic. You must stop them before running `kinetic daemon`.
