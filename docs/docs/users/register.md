# Registering a Name

A `.kin` name is yours forever once registered. There are no annual renewals, no fees, and no central authority. Ownership is proven by a **Verifiable Delay Function (VDF)** — a computation your CPU must run for a fixed amount of real clock time. There is no shortcut.

---

## Name format rules

Valid `.kin` names follow DNS LDH rules:

- **Allowed:** lowercase letters (`a–z`), digits (`0–9`), hyphens (`-`)
- **Not allowed:** uppercase letters, spaces, underscores, dots in the label, special characters
- **Cannot start or end with a hyphen**: `-name.kin` and `name-.kin` are rejected
- **Cannot start with a digit**: `007.kin` is rejected
- **Must end in `.kin`**: only this TLD is supported
- **Subdomains cannot be registered directly**: `blog.myname.kin` is not a registerable apex name — you register `myname.kin` and add `blog` as a subdomain label in your zone file

| Name | Valid? | Reason |
|---|---|---|
| `myapp.kin` | ✅ | |
| `my-cool-site.kin` | ✅ | |
| `saif123.kin` | ✅ | |
| `MyApp.kin` | ❌ | Uppercase not allowed |
| `my_app.kin` | ❌ | Underscores not allowed |
| `-name.kin` | ❌ | Cannot start with hyphen |
| `007.kin` | ❌ | Cannot start with digit |
| `blog.myname.kin` | ❌ | Not an apex name |

### Reserved names

These names are permanently locked and cannot be registered:

`test`, `example`, `invalid`, `localhost`, `local`, `onion`, `arpa`, `null`, `none`, `zero`, `corp`, `lan`, `internal`

Additionally, certain infrastructure names (`docs.kin`, `seed.kin`, etc.) are reserved for network use until Phase 2.

---

## How long does registration take?

Registration time depends on your name's length. Shorter names require more VDF iterations to prevent squatting:

| Name length | Approximate time |
|---|---|
| 2 characters | ~30 days |
| 3 characters | ~24 days |
| 4 characters | ~15 days |
| 5 characters | ~1 day |
| 6 characters | ~12 hours |
| 7 characters | ~2.5 hours |
| 8–10 characters | ~2 hours |
| 11–17 characters | ~1.5 hours |
| 18–20 characters | ~1 hour |
| 21–62 characters | Baseline (hardware target) |
| 63 characters | Randomized (63 seconds to 63 millennia) |

::: warning Your CPU runs at full load during VDF
This is normal and expected. The computation is single-threaded and will saturate one CPU core for the entire duration. Do not close the daemon.
:::

---

## Option A: Register via the Desktop App

1. Open Kinetic Desktop → **Names** section
2. Type your name in the **Register** field (e.g. `myapp.kin`)
3. Click **Register**
4. A progress bar appears showing VDF computation in real time
5. When progress reaches 100%, your name is live — the daemon has already broadcast it to the network
6. Go to the **Names** section, select your name, and add your DNS records
7. Click **Save & Publish** to push the records live

---

## Option B: Register via the CLI

```bash
kinetic name register myapp.kin
```

Check progress:

```bash
kinetic name info myapp.kin
```

When registration completes, add DNS records by editing the zone file:

```
~/.local/share/kinetic/zones/myapp.kin.json        # Linux
~/Library/Application Support/kinetic/zones/myapp.kin.json  # macOS
%LOCALAPPDATA%\kinetic\zones\myapp.kin.json         # Windows
```

Then publish:

```bash
kinetic name publish myapp.kin
```

Verify it is live:

```bash
dig @127.0.0.2 myapp.kin A
```

---

## What happens during registration

The daemon runs the full pipeline automatically:

1. **Fetches drand randomness** — a public randomness beacon used to seed the VDF computation
2. **Generates a commitment** — a blind hash of your name + randomness, published to the DHT before the VDF is done (prevents front-running)
3. **Computes the VDF** — CPU-intensive, takes hours depending on name length
4. **Broadcasts the commitment** — announces to the network that you've started
5. **Waits 32 seconds** — a mandatory maturation window for the commitment
6. **Publishes the registration** — submits the full signed proof to the DHT

Only step 3 takes a long time. Everything else is fast.

---

## If someone else registers the same name first

The commitment system protects against front-running: your commitment is published before anyone can see your full proof. If two users commit to the same name simultaneously, the network resolves the conflict by VDF difficulty — the proof with more iterations wins.

In practice, conflicts on names longer than 4 characters are extremely rare.

---

## After registration

Once registered, your name appears in `kinetic name list` (CLI) or in the **Names** dropdown (desktop app). Registration leaves an empty zone — no DNS records are published yet.

To make your name actually resolve to something:
1. Edit your zone file or use the desktop app's Names editor
2. Add at least one record (e.g. an `A` record pointing to your server's IP)
3. Publish the zone

See [DNS Records](/users/dns-records) for the full record format reference.
