# TypeScript SDK

The Kinetic TypeScript SDK is a strongly-typed client generated from the Kinetic OpenAPI specification. It wraps every REST endpoint into an async method with full TypeScript types.

## Installation

The SDK lives in the `kinetic-sdk` repository and is published to npm. You can install it directly in your project:

```bash
npm install @kinetic-sdk/ts
```

Import from it:

```typescript
import { Configuration, PublicApi, AuthenticatedApi } from '@kinetic-sdk/ts';
```

## Example Application

If you'd like to see a full, production-ready React web application using the TypeScript SDK, check out the `kinetic-article` submodule in our examples folder:

[View `kinetic-article` Example on GitHub](https://github.com/saifmukhtar/kinetic-article)

## Setup & Authentication

The SDK exposes two classes:

- **`PublicApi`** — endpoints that need no authentication (resolve, network status)
- **`AuthenticatedApi`** — endpoints that require the daemon's bearer token

The bearer token is stored by the daemon in your data directory and is regenerated on every restart:

| OS | Token path |
|---|---|
| Linux | `~/.local/share/kinetic/api.token` |
| macOS | `~/Library/Application Support/kinetic/api.token` |
| Windows | `%APPDATA%\kinetic\api.token` |

```typescript
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Configuration, PublicApi, AuthenticatedApi } from '@kinetic-sdk/ts';

function tokenPath(): string {
  switch (process.platform) {
    case 'darwin':
      return path.join(os.homedir(), 'Library', 'Application Support', 'kinetic', 'api.token');
    case 'win32':
      return path.join(process.env.APPDATA!, 'kinetic', 'api.token');
    default: // linux and others
      return path.join(os.homedir(), '.local', 'share', 'kinetic', 'api.token');
  }
}

// Daemon must be running before you read the token
const token = fs.readFileSync(tokenPath(), 'utf8').trim();

const config = new Configuration({
  basePath: 'http://127.0.0.1:16002/api',
  accessToken: token
});

const publicApi = new PublicApi(config);
const authenticatedApi = new AuthenticatedApi(config);
```

::: tip PublicApi doesn't need a token
`new PublicApi(new Configuration({ basePath: 'http://127.0.0.1:16002/api' }))` is sufficient for resolve and network status calls — no token file needed.
:::

---

## PublicApi Reference

### `networkStatusGet()`

Returns network connectivity status from the daemon.

- **Auth**: Not required
- **Returns**: `Promise<object>`

```typescript
const status = await publicApi.networkStatusGet();
console.log(status);
```

---

### `resolveNameGet({ name })`

Resolves a `.kin` name and returns the full `Reveal` record published to the DHT.

- **Auth**: Not required
- **Parameters**: `{ name: string }` — e.g. `'myname.kin'`
- **Returns**: `Promise<Reveal>`

The `Reveal` object contains:

| Field | Type | Description |
|---|---|---|
| `name` | `string` | Fully qualified name |
| `pubkey` | `number[]` | Owner's ML-DSA-65 public key bytes |
| `drand_pulse` | `number` | Drand randomness round used during registration |
| `iterations` | `number` | VDF difficulty (iteration count) |
| `vdf_proof` | `object` | The VDF proof bytes |
| `signature` | `number[]` | Owner's signature over the reveal |
| `payload` | `number[]` | Serialised DNS zone bytes |

```typescript
const reveal = await publicApi.resolveNameGet({ name: 'myname.kin' });
console.log(reveal.drand_pulse, reveal.iterations);
```

---

### `resolveKidDidGet({ did })`

Resolves a `did:kin:` identity from the DHT.

- **Auth**: Not required
- **Parameters**: `{ did: string }` — e.g. `'did:kin:abc123...'`
- **Returns**: `Promise<ResolveKidDidGet200Response>`

---

### `zoneNameGet({ name })`

Returns the local DNS zone for a given name (from daemon-local storage).

- **Auth**: Not required
- **Parameters**: `{ name: string }`
- **Returns**: `Promise<DnsZone>`

`DnsZone` shape:
```typescript
{
  records?: {
    [label: string]: Array<{ type: string; value: string }>
  }
}
```

Label `"@"` is the apex record. Supported types: `A`, `AAAA`, `CNAME`, `TXT`, `PeerId`, `KID`.

---

## AuthenticatedApi Reference

### `vdfRegisterPost({ vdfRegisterRequest })`

Starts a full name registration inside the daemon as a background task. The daemon handles everything: drand fetch, VDF computation, commitment broadcast, 32-second maturation window, and DHT publication. When the task reaches `status === 'Complete'` and `progress === 100`, the name is live on the network.

- **Auth**: Required
- **Parameters**: `{ vdfRegisterRequest: { name: string } }`
- **Returns**: `Promise<{ task_id: string; message: string }>`

::: warning Registration time
This takes 30 minutes to many hours depending on name length. The daemon's CPU will be fully loaded. Only one registration task can run at a time — a second call returns HTTP 409.
:::

---

### `vdfRenewPost({ nameRenewRequest })`

Renews an existing name. Identical flow to registration, but uses the previous reveal as a chain link. Renewal iterations are discounted to 20% of the full registration requirement.

- **Auth**: Required
- **Parameters**: `{ nameRenewRequest: { name: string } }`
- **Returns**: `Promise<{ task_id: string; message: string }>`

---

### `vdfStatusTaskIdGet({ taskId })`

Polls the progress of a VDF task.

- **Auth**: Required
- **Parameters**: `{ taskId: string }`
- **Returns**: `Promise<VdfTaskStatus>`

`VdfTaskStatus` shape:

| Field | Type | Description |
|---|---|---|
| `status` | `string` | Human-readable phase name (see below) |
| `progress` | `number` | Completion percentage — `0` to `100` |
| `iterations` | `number` | Total VDF iterations planned |
| `error` | `string \| null` | Error message, or `null` if none |

**Status values from the daemon:**

| `status` value | Meaning |
|---|---|
| `"Initializing"` | Task just created |
| `"Fetching Drand beacon"` | Getting randomness |
| `"Generating Commitment"` | Building the commitment hash |
| `"Computing VDF... (this may take a while)"` | CPU-bound computation running |
| `"Broadcasting Commitment"` | Pushing commitment to DHT |
| `"Maturing commitment (32 s)..."` | Waiting 32 seconds for commit maturation |
| `"Publishing Registration"` | Submitting signed reveal to DHT |
| `"Complete"` | ✅ Done — name is live |
| `"Failed"` | ❌ Error — check the `error` field |

::: danger Check for `"Complete"` not `"completed"`
The completion status string is exactly `"Complete"` (capital C). Do not check for `"completed"` — it will never match.
:::

---

### `vdfStatusTaskIdDelete({ taskId })`

Removes a completed or failed task's record from daemon memory. Call this after you're done with a task.

- **Auth**: Required
- **Parameters**: `{ taskId: string }`
- **Returns**: `Promise<{ success: boolean }>`

---

### `ownedNamesGet()`

Returns the list of all names registered through this daemon.

- **Auth**: Required
- **Returns**: `Promise<string[]>`

---

### `zoneNamePost({ name, dnsZone })`

Save or update the local DNS zone for a name. This writes to daemon-local storage only. Call `zoneNamePublishPost` afterward to push it live.

- **Auth**: Required
- **Parameters**: `{ name: string; dnsZone: DnsZone }`
- **Returns**: `Promise<void>`

---

### `zoneNamePublishPost({ name })`

Cryptographically sign and publish the current local zone for a name to the DHT network. After this, anyone resolving the name will see the updated records.

- **Auth**: Required
- **Parameters**: `{ name: string }`
- **Returns**: `Promise<void>`

---

### `commitPost`, `publishPost`, `publishKidPost`, `publishManifestPost`

Lower-level DHT publishing endpoints. These are used by the CLI for manual registration flows and advanced use cases. For normal registration, use `vdfRegisterPost` instead — it handles the full flow.

---

### `configGet()` / `configPost({ configPostRequest })`

Read or update daemon configuration.

- **Auth**: Required
- `configPost` parameters: `{ configPostRequest: { mode?: string } }`

---

## Error Handling

When the API returns an error response, the SDK throws an exception. The response body contains a `KIN-XXX-NNN` error code you can match against:

```typescript
try {
  const reveal = await publicApi.resolveNameGet({ name: 'unknown.kin' });
} catch (error: any) {
  if (error.response) {
    const body = await error.response.json();
    switch (body.code) {
      case 'KIN-RES-002':
        console.log('Name not found on the network.');
        break;
      case 'KIN-RES-001':
        console.error('Daemon has no DHT peers — check network connectivity.');
        break;
      default:
        console.error(`API error [${body.code}]: ${body.message}`);
    }
  } else {
    // Could not reach the daemon at all
    console.error('Cannot connect to kinetic-daemon:', error.message);
  }
}
```

See the [Error Code Reference](/users/errors) for the full list of `KIN-*` codes.

---

## Regenerating the SDK

The SDK is generated from `/home/saif/kinetic-sdk/openapi.yaml`. If the API changes, regenerate with:

```bash
npx @openapitools/openapi-generator-cli generate \
  -i openapi.yaml \
  -g typescript-fetch \
  -o ./typescript
```

Do not edit the generated files manually.
