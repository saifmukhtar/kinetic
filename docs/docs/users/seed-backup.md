# Seed Phrase & Backup

Your seed phrase is the ultimate master key to your Kinetic identity. If your computer crashes, your hard drive fails, or you move to a new machine, your seed phrase is the **only way** to recover your identity and the names you own.

## What is a Seed Phrase?

A seed phrase is a human-readable list of 12 words (following the BIP-39 standard). It looks like this:

`apple banana cherry dog elephant frog grape house igloo jacket kite lemon` *(Example only, do not use!)*

These 12 words mathematically generate your master private key (`identity.key`).

::: danger
**Never share your seed phrase with anyone, ever.** Kinetic support, developers, or community members will never ask for it. Anyone who has your seed phrase can steal all of your names permanently.
:::

## How to View Your Seed Phrase

If you haven't written it down yet, you can view your seed phrase by opening a terminal and running:

```bash
kinetic seed show
```

## How to Back It Up

- **Write it down on paper:** Use a pen and paper. Ensure the words are spelled correctly and in the exact order.
- **Keep it offline:** Do not store it unencrypted in a text file, email it to yourself, or take a photo of it with your phone.
- **Secure location:** Store the paper in a fireproof safe, a lockbox, or a secure physical location.

## How to Restore Your Identity

If you need to recover your identity on a new computer, install the Kinetic daemon, then run:

```bash
kinetic seed restore
```

The CLI will prompt you to type in your 12 words. Once entered correctly, your `identity.key` will be regenerated. Once you start the daemon and it connects to the DHT network, your existing names will become accessible again.

## Critical: VDF Proof Files

While your seed phrase recovers your identity, it **does not** recover your VDF proof files. 

When you register a name, the daemon saves a file like `myname.kin.reveal.json`. This file contains the cryptographic proof of the time you spent registering the name.

If you lose this file, you cannot publish updates to your DNS records for that name, even if you recover your identity key.

**Always back up the `zones/` directory.** See the [File Paths Guide](/users/file-paths) for where to find it.
