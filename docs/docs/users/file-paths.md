# File Paths & Data Directory

The Kinetic daemon creates and maintains several files on your system. It is important to know where these live, especially for backups and troubleshooting.

## Default Data Directory

The data directory location depends on your operating system:

| Operating System | Default Path |
| :--- | :--- |
| **Linux** | `~/.local/share/kinetic/` |
| **macOS** | `~/Library/Application Support/kinetic/` |
| **Windows** | `%APPDATA%\kinetic\` |

## Important Files

Inside the data directory, you will find the following critical files and folders:

| File / Folder | Description | Action |
| :--- | :--- | :--- |
| `identity.key` | Your Ed25519 private key (32 bytes). This is the binary form of your identity. | **BACKUP.** Protect this heavily. |
| `identity.mnemonic` | Your 12-word BIP-39 seed phrase in plain text. | **BACKUP.** Protect this heavily. |
| `api.token` | Bearer token for the local REST API. Regenerated on each daemon start. | Safe to delete. |
| `sled_db/` | Local embedded database containing network state. Do not manually edit. | Safe to delete (daemon will resync). |
| `zones/` | Directory containing your DNS zone files. | |
| `zones/NAME.json` | Your DNS zone file (e.g., `myname.kin.json`). Edit this to update records. | **BACKUP.** |
| `zones/NAME.reveal.json` | The VDF proof file generated when you registered the name. | **CRITICAL BACKUP.** |
| `ca_cert.pem` | Local Certificate Authority cert for HTTPS interception (proxy mode). | Safe to delete. |
| `.ca.lock` | Lock file for CA generation. | Safe to delete. |

## Binary Locations

When you install Kinetic via the official script, the executables are placed in your system's path:

- **Linux / macOS:** `/usr/local/bin/kinetic` and `/usr/local/bin/kinetic-daemon`
- **Windows:** `C:\Program Files\Kinetic\kinetic.exe` and `C:\Program Files\Kinetic\kinetic-daemon.exe`

## Logs

By default, the `kinetic-daemon` prints all its logs directly to the terminal (stdout/stderr). 
If you are running it as a background service (like systemd), the logs are handled by the service manager. 

To save logs to a file manually, you can redirect the output:
```bash
sudo kinetic daemon > kinetic.log 2>&1
```
