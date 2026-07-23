# Seed Backup

Your **24-word seed phrase** is the master key to your Kinetic identity. Every name you register is controlled by the cryptographic keypair derived from this phrase. If you lose both your device and your seed phrase, your names are unrecoverable.

---

## When is the seed shown?

**Only once** — during initial setup, when you run `kinetic setup` (CLI) or click **Generate Master Seed** (desktop app).

There is no "show my seed" command or button. The daemon stores the derived private key (`identity.key`) — not the seed phrase itself. The seed phrase is **never saved to your computer**.

---

## Back up your seed phrase

Write down all 24 words, in order, on paper. During CLI setup, you will be asked to re-type two random words to verify your backup.

::: danger Do this before closing the setup screen
Once you dismiss the seed display, it does not appear again.
:::

**Good backup practices:**

- Write it on paper — not in a notes app, not in a screenshot, not in cloud storage
- Store it somewhere physically secure (safe, safety deposit box)
- Consider making two copies and storing them in different locations
- Never share it digitally — anyone who has these 24 words controls your names

---

## Restoring from your seed phrase

If you install Kinetic on a new machine and need to restore your identity:

### Desktop app

1. Open **Kinetic Desktop** → **Identity** section
2. In the **Restore Identity** panel, paste your 24 words (space-separated)
3. Click **Restore & Restart**

The daemon restarts and your identity is restored. Your registered names are tied to the cryptographic keypair — once the identity is restored, you can manage them again.

### CLI

```bash
kinetic setup
```

When prompted, choose to restore from an existing phrase and enter your 24 words.

---

## Full data directory

For reference, the complete set of important files:

| File | Contents | Sensitivity |
|---|---|---|
| `identity.key` | 32-byte Ed25519 private key | 🔴 Never share — full account control |
| `api.token` | Local API bearer token | 🟡 Safe within your machine; regenerated on daemon restart |
| `zones/yourname.kin.json` | DNS zone records | 🟢 Not sensitive |

---

## What is the seed phrase exactly?

It is a **BIP-39 mnemonic** — 24 words from a standardized English word list, encoding 256 bits of entropy. From this seed, an Ed25519 keypair is derived deterministically using PBKDF2-HMAC-SHA512 with 600,000 iterations. The same 24 words always produce the same keypair, on any machine, using any compatible BIP-39 tool.

The seed is generated using `getrandom` (cryptographically secure OS randomness) — not a user password, not a clock-based seed.
