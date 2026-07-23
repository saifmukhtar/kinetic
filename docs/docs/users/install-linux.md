# Install Kinetic on Linux

This guide will walk you through installing the Kinetic daemon on your Linux machine.

## Prerequisites
- You need `sudo` or root access on your machine, as the Kinetic daemon must listen on port 53 to resolve DNS queries.
- `curl` should be installed on your system.

## Installation Steps

Open your terminal and run the following command to download and execute the installer script:

```bash
curl -sSL https://kinetic.saifmukhtar.dev/install.sh | bash
```

**What this does:**
1. Downloads the latest Kinetic binaries (`kinetic` and `kinetic-daemon`) and installs them to `/usr/local/bin`.
2. Creates the Kinetic data directory at `~/.local/share/kinetic/`.

### 1. Verify the Installation

To verify that the CLI was installed correctly, run:

```bash
kinetic --version
kinetic daemon --help
```

### 2. Start the Daemon

The Kinetic daemon handles name resolution and background tasks. You must run it with `sudo` so it can access port 53.

```bash
sudo kinetic daemon
```

Look for the message `"Connected to DHT"` in the output logs. This confirms your daemon has successfully joined the network.

### 3. Initialize Your Identity

If this is your first time running Kinetic, you must generate a new identity. Open a **new terminal window** (leave the daemon running) and execute:

```bash
kinetic seed init
```

::: danger
This command generates your master seed phrase. Follow the instructions on the screen to back it up immediately! See the [Seed Backup Guide](/users/seed-backup) for more details.
:::

## Running as a Service (systemd)

To keep the Kinetic daemon running in the background and automatically start it on boot, you can create a `systemd` service.

1. Create a file at `/etc/systemd/system/kinetic.service`:

```ini
[Unit]
Description=Kinetic Network Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/kinetic-daemon
Restart=always
User=root
Environment=HOME=/root

[Install]
WantedBy=multi-user.target
```

2. Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kinetic.service
```

## Common Issues

### Port 53 Already in Use
On Ubuntu, `systemd-resolved` often occupies port 53.
To fix this, disable the stub listener:
```bash
sudo systemctl disable --now systemd-resolved
```
Then, update your `/etc/resolv.conf` to point to localhost:
```bash
sudo rm /etc/resolv.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
```

### Permission Denied
If you see a permission denied error when starting the daemon, ensure you are using `sudo kinetic daemon`. Port 53 is a privileged port on Linux.
