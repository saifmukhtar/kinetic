# DNS Records

Once you own a `.kin` name, you manage its DNS records using a local zone file. This file dictates where traffic for your domain (and subdomains) should go.

## Where is the Zone File?

The zone file is created automatically when your name registration finishes. It is named `YOURNAME.kin.json`.

- **Linux:** `~/.local/share/kinetic/zones/YOURNAME.kin.json`
- **macOS:** `~/Library/Application Support/kinetic/zones/YOURNAME.kin.json`
- **Windows:** `%APPDATA%\kinetic\zones\YOURNAME.kin.json`

## Zone File Format

The file is written in standard JSON. Here is an example of what it looks like:

```json
{
  "records": {
    "@": [
      { "type": "A", "value": "1.2.3.4" },
      { "type": "TXT", "value": "v=spf1 include:example.com" }
    ],
    "www": [
      { "type": "CNAME", "value": "myname.kin." }
    ],
    "p2p": [
      { "type": "PeerId", "value": "12D3KooWD...xyz" }
    ]
  }
}
```

- `@` represents the apex (root) of your domain (e.g., just `myname.kin`).
- `www` and `p2p` are subdomains (e.g., `www.myname.kin`, `p2p.myname.kin`).

::: warning
Subdomains can only be managed by the apex name owner. You cannot register a `.kin` subdomain directly using the `kinetic name register` command.
:::

## Supported Record Types

Kinetic supports several standard and specialized record types:

- **A**: Maps the name to an IPv4 address.
  - `{"type": "A", "value": "1.2.3.4"}`
- **AAAA**: Maps the name to an IPv6 address.
  - `{"type": "AAAA", "value": "2001:db8::1"}`
- **CNAME**: Aliases the name to another domain name. Must end with a dot if it's an absolute name.
  - `{"type": "CNAME", "value": "example.com."}`
  - *Rule:* A CNAME cannot exist on the same label alongside any other records.
- **TXT**: Arbitrary text data, often used for verification or SPF rules.
  - `{"type": "TXT", "value": "hello world"}`
- **PeerId**: A libp2p Peer ID used for direct peer-to-peer application discovery.
  - `{"type": "PeerId", "value": "12D3KooW..."}`
- **KID**: A Kinetic Identity reference (`did:kin:...`).
  - `{"type": "KID", "value": "did:kin:..."}`

### Limits
- You can have a maximum of **50 records** per zone file.
- `TXT` records are limited to a maximum of **255 bytes**.

## Applying Changes

Editing the JSON file on your computer does not automatically update the global network. After saving your changes to the file, you must tell the Kinetic daemon to publish them:

```bash
kinetic name publish myname.kin
```

## Verifying Changes

You can verify your DNS records are working locally using the `dig` command:

```bash
dig @127.0.0.1 myname.kin A
```
*(Replace `A` with the record type you are querying)*
