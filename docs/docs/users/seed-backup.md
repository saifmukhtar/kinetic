# Seed Phrase & Backup

Your seed phrase is the ultimate master key to your Kinetic identity. If your computer crashes, your hard drive fails, or you move to a new machine, your seed phrase is the **only way** to recover your identity and the names you own.

## What is a Seed Phrase?

A seed phrase is a human-readable list of **24 words** (following the BIP-39 standard). It looks like this:

```
abandon zoo pizza cloud forest desert ocean signal window marble tower
bridge circuit copper dawn eagle falcon grape harbor iron jungle kite lamp
```
*(Example only — never use this.)*

These 24 words mathematically generate your master private key (`identity.key`).

::: danger Never share your seed phrase
Anyone who has your seed phrase can steal all of your names permanently. Kinetic support, developers, and community members will **never** ask for it. If someone does, it is a scam.
:::

## When Does the Seed Appear?

Your seed phrase is shown **exactly once** — when you run `kinetic seed init` or `kinetic setup` for the first time. The CLI prints all 24 words, then prompts you to verify two random words before it continues.

**There is no `kinetic seed show` command.** If you did not write down your seed phrase at creation time, and you no longer have the `identity.key` file, your identity is not recoverable.

::: tip If your daemon is still running
If your `identity.key` file still exists on disk, your identity is fine — you just cannot view the seed phrase again. Your names are accessible as long as your `identity.key` is intact.
:::

## How to Back It Up

During `kinetic seed init`, you have one window to write it down. Here is the right way:

1. **Write on paper** — use a pen, not a printer. Check spelling and order carefully.
2. **Make two copies** — store them in separate locations.
3. **Keep it offline** — never in a plain text file, email, photo, or cloud document.
4. **Secure location** — a fireproof safe, lockbox, or safety deposit box.

The 24 words must be in the correct order. Word 1 written in the wrong position = unrecoverable.

## How to Restore Your Identity

If you need to recover your identity on a new machine:

1. Install Kinetic (see [Install on Linux](/users/install-linux), [macOS](/users/install-macos), or [Windows](/users/install-windows))
2. Run the restore command:

```bash
kinetic seed restore
```

The CLI will prompt for your 24-word phrase (input is hidden, like a password). Type all 24 words separated by spaces and press Enter.

Once your `identity.key` is restored:
- Start the daemon: `kinetic daemon start`
- Your names become accessible again once the daemon reconnects to the DHT network

::: warning After restoring on a new machine
Copy your `zones/*.reveal.json` proof files from your old machine (or backup) to the zones directory on the new machine. Without them, you cannot publish DNS updates.
:::

## Critical: VDF Proof Files

Your seed phrase recovers your **identity key** — but it does **not** recover your VDF proof files.

When you register a name, the daemon saves:

```
~/.local/share/kinetic/zones/myname.kin.reveal.json
```

This file contains the cryptographic proof of the computational work you did to register the name. Without it, you cannot publish DNS updates for that name, even if you have a perfectly intact `identity.key`.

**Back up the entire `zones/` directory**, not just your seed phrase.

See [File Paths Reference](/users/file-paths) for exact directory locations on each OS.
