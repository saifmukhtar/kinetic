# Troubleshooting

If you are experiencing issues with Kinetic, check the scenarios below for solutions.

## Daemon won't start

### Port 53 already in use
This is very common on Ubuntu systems because `systemd-resolved` binds to port 53.
**Fix:** Disable the stub listener:
```bash
sudo systemctl disable --now systemd-resolved
```
Then edit `/etc/resolv.conf` to point to `127.0.0.1`:
```bash
sudo rm /etc/resolv.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
```

### Permission denied on port 53
On Linux and macOS, port 53 is a privileged port. 
**Fix:** You must start the daemon as an administrator using `sudo`:
```bash
sudo kinetic daemon
```

### Database locked (KIN-STO-001)
Another instance of the Kinetic daemon is already running in the background.
**Fix:** Kill the existing process. On Linux/macOS, run `sudo pkill kinetic-daemon`. On Windows, use the Task Manager to end it.

### Identity not found (KIN-IDN-003)
The daemon requires an identity key to start, but none was found.
**Fix:** Run `kinetic seed init` to generate a new identity.

## Not connecting to network (No peers)

If you see errors like **KIN-NET-003** (routing table empty) or **KIN-RES-001** (node offline), your node cannot talk to the network.
- Check your internet connection.
- Ensure your router or firewall is not blocking outbound TCP traffic on port `6070` (the Kinetic P2P port).
- Restart the daemon; it will attempt to bootstrap connection to peers again.

## DNS not resolving in browser

If your browser shows "site not found" for `.kin` names:
- Make sure the daemon is actually running in a terminal or as a service.
- Check if DNS is working locally by running `dig @127.0.0.1 myname.kin A`.
- **macOS:** Verify the daemon is listening on port 53 by running `sudo lsof -i :53`.
- **Windows:** Ensure the Windows DNS Client service isn't blocking port 53.
- Ensure the name has been published: run `kinetic name resolve myname.kin`. If it isn't found, you may need to run `kinetic name publish myname.kin`.

## VDF computation seems stuck

If you started a registration or renewal and it seems like nothing is happening:
- **This is normal.** VDF computation is silent and takes a long time. Your CPU should be working hard. Use `kinetic name info myname.kin` in another terminal to check the status.
- **KIN-VDF-001/002:** Only one VDF task can run at a time. If you see lock errors, wait for the current task to finish.
- If it has taken hours longer than the expected time for your name length, you can safely restart the daemon. The computation will resume from its last checkpoint.

## Name not found (KIN-RES-002)

- **If you just registered it:** You probably haven't published it yet. Edit your zone file, then run `kinetic name publish myname.kin`.
- **If you just published it:** It takes a few minutes for the name to propagate across the DHT network. Wait a few minutes and try again.
- Verify you actually own the name by running `kinetic name list`.

## Drand errors (KIN-DRA-001, KIN-DRA-002)

The daemon uses the Drand network to fetch random challenges for the VDF. 
- If you see these errors, it means your computer cannot reach the Drand beacon. Check your internet connection.
- If you are on a corporate network or strict firewall, ensure HTTPS traffic to `drand.cloudflare.com` is permitted.

## Seed/Identity Errors

### Invalid seed phrase (KIN-IDN-004)
If you are trying to restore, check your spelling carefully. All 12 words must be valid English words from the official BIP-39 dictionary.

### Lost Seed and Key
If your hard drive crashes and you lose both the `identity.key` file AND your paper seed phrase backup, **recovery is impossible**. Ownership of your `.kin` names is permanently lost.
