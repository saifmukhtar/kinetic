# DNS Records

After registering a name, you control what it resolves to by editing its **DNS zone**. A zone maps labels (like `@` for the root, `www`, `api`) to records like IP addresses, text strings, or Kinetic-native types.

---

## Where is the zone file?

| OS | Path |
|---|---|
| Linux | `~/.local/share/kinetic/zones/yourname.kin.json` |
| macOS | `~/Library/Application Support/kinetic/zones/yourname.kin.json` |
| Windows | `%LOCALAPPDATA%\kinetic\zones\yourname.kin.json` |

The file is plain JSON. You can edit it with any text editor.

---

## Zone file format

```json
{
  "records": {
    "@": [
      { "type": "A", "value": "1.2.3.4" },
      { "type": "TXT", "value": "v=spf1 include:example.com ~all" }
    ],
    "www": [
      { "type": "CNAME", "value": "myapp.kin." }
    ],
    "api": [
      { "type": "A", "value": "5.6.7.8" }
    ]
  }
}
```

- `"@"` is the **apex** — the root of your name (`myapp.kin` itself)
- Other keys are **labels** — they become subdomains (`www.myapp.kin`, `api.myapp.kin`)
- Each label maps to an array of record objects, each with a `"type"` and `"value"`
- Labels are **case-insensitive** — the daemon lowercases them on parse
- Wildcard label `"*"` is supported — matches any unresolved subdomain

---

## Record types

### `A` — IPv4 address

```json
{ "type": "A", "value": "1.2.3.4" }
```

Points your name to an IPv4 address. Use for web servers, game servers, any TCP/UDP service.

### `AAAA` — IPv6 address

```json
{ "type": "AAAA", "value": "2001:db8::1" }
```

Same as `A` but for IPv6.

### `CNAME` — Canonical Name alias

```json
{ "type": "CNAME", "value": "myapp.kin." }
```

Aliases one label to another domain. The trailing dot is conventional DNS notation — it works with or without it.

::: warning CNAME cannot coexist with other records
If a label has a `CNAME`, it cannot have any other records (`A`, `TXT`, etc.) for the same label. This is a DNS protocol requirement enforced by the daemon. Attempting it will fail validation.
:::

### `TXT` — Text record

```json
{ "type": "TXT", "value": "any text up to 255 bytes" }
```

Use for: domain verification strings, SPF records, metadata, application-specific data.

- Maximum **255 bytes** per TXT record value

### `PeerId` — libp2p Peer ID

```json
{ "type": "PeerId", "value": "12D3KooWNvSVhMTBqYq5..." }
```

A libp2p peer ID pointing to a P2P node. Use this so applications can discover your node by resolving your `.kin` name. The value must be a valid libp2p PeerId string — the daemon validates it on save.

### `KID` — Kinetic Identity reference

```json
{ "type": "KID", "value": "did:kin:abc123..." }
```

Links your name to a `did:kin:` decentralized identity document. The value must start with `did:kin:` — other DID methods are rejected.

### `IPFS` — IPFS Content Identifier

```json
{ "type": "IPFS", "value": "QmYwAPJzv5CZsnA..." }
```

An IPFS CID pointing to content. Supports both CIDv0 (starts with `Qm`) and CIDv1 (starts with `b`). Maximum 100 characters.

---

## Limits

| Constraint | Limit |
|---|---|
| Total records per zone | **50 maximum** |
| TXT record value | **255 bytes maximum** |
| CNAME target length | **253 characters maximum** |
| Label length | **1–63 characters** |
| IPFS CID length | **100 characters maximum** |
| JSON nesting depth | **10 levels maximum** (DoS protection) |

---

## Managing records via the Desktop App

1. Open **Kinetic Desktop** → **Names** section
2. Select your name from the dropdown
3. Add rows using the **+** button — choose the record type and enter the value
4. Delete rows with the trash icon
5. **Save Draft** — writes to local storage only (not visible on the network)
6. **Save & Publish** — saves draft and signs + publishes to the DHT in one step

Changes are not visible on the network until you publish.

---

## Managing records via the CLI

Edit the zone file directly:

```bash
nano ~/.local/share/kinetic/zones/myapp.kin.json
```

Then publish:

```bash
kinetic name publish myapp.kin
```

---

## Verifying your records are live

After publishing, test with `dig`.

Query your local daemon:

```bash
dig @127.0.0.2 myapp.kin A
```

Query a specific subdomain:

```bash
dig @127.0.0.2 www.myapp.kin CNAME
```

Or use the **Resolver** section in the desktop app — type your name and click Resolve.

---

## Subdomains

Subdomains are just labels in your zone file. You don't register them separately — they're part of your apex name's zone.

```json
{
  "records": {
    "@":    [{ "type": "A", "value": "1.2.3.4" }],
    "www":  [{ "type": "CNAME", "value": "myapp.kin." }],
    "api":  [{ "type": "A", "value": "1.2.3.5" }],
    "blog": [{ "type": "A", "value": "1.2.3.6" }],
    "*":    [{ "type": "A", "value": "1.2.3.4" }]
  }
}
```

The `"*"` wildcard entry catches any subdomain not explicitly listed. Only the apex name owner can add or change these records.
