# TypeScript SDK

The Kinetic TypeScript SDK provides a complete, strongly-typed wrapper around the Kinetic REST API. It is generated automatically from our OpenAPI specifications.

## Installation

You can install the SDK directly via npm (assuming you have access to the published package) or link it locally from the `/home/saif/kinetic-sdk` repository.

```bash
npm install kinetic-sdk
```

## Initialization & Authentication

The SDK exports `PublicApi` (for endpoints that do not require authentication) and `AuthenticatedApi` (for endpoints that do). Both accept a `Configuration` object.

To use the `AuthenticatedApi`, you must read the daemon's API token from the local filesystem.

```typescript
import * as fs from 'fs';
import { Configuration, PublicApi, AuthenticatedApi } from 'kinetic-sdk';

// 1. Read token from file (daemon must be running)
const tokenPath = `${process.env.HOME}/.local/share/kinetic/api.token`;
const token = fs.readFileSync(tokenPath, 'utf8').trim();

// 2. Setup Configuration
const config = new Configuration({
  basePath: 'http://127.0.0.1:16002/api',
  accessToken: token
});

// 3. Instantiate APIs
const publicApi = new PublicApi(config);
const authenticatedApi = new AuthenticatedApi(config);
```

## PublicApi Reference

The `PublicApi` class contains methods that do not require an `accessToken`.

### `networkStatusGet()`
Returns the network connectivity status.
- **Returns:** `Promise<object>`

### `resolveNameGet(requestParameters)`
Resolves a Kinetic name.
- **Parameters:** `{ name: string }`
- **Returns:** `Promise<Reveal>`

### `resolveKidDidGet(requestParameters)`
Resolves a KID document.
- **Parameters:** `{ did: string }`
- **Returns:** `Promise<{kid_document, manifest_document}>`

### `zoneNameGet(requestParameters)`
Gets the DNS zone for a name.
- **Parameters:** `{ name: string }`
- **Returns:** `Promise<DnsZone>`

## AuthenticatedApi Reference

The `AuthenticatedApi` class contains methods that manage names and configurations.

### `vdfRegisterPost(requestParameters)`
Starts a VDF task to register a name.
- **Parameters:** `{ vdfRegisterRequest: { name: string } }`
- **Returns:** `Promise<{task_id: string, message: string}>`

### `vdfRenewPost(requestParameters)`
Starts a VDF task to renew a name.
- **Parameters:** `{ nameRenewRequest: { name: string } }`
- **Returns:** `Promise<{task_id: string, message: string}>`

### `vdfStatusTaskIdGet(requestParameters)`
Checks the status of a VDF task.
- **Parameters:** `{ taskId: string }`
- **Returns:** `Promise<VdfTaskStatus>`

### `vdfStatusTaskIdDelete(requestParameters)`
Cancels or cleans up a VDF task.
- **Parameters:** `{ taskId: string }`
- **Returns:** `Promise<{success: boolean}>`

### `ownedNamesGet()`
Lists all locally owned names.
- **Returns:** `Promise<string[]>`

### `zoneNamePost(requestParameters)`
Updates local DNS records for an owned name.
- **Parameters:** `{ name: string, dnsZone: DnsZone }`
- **Returns:** `Promise<void>`

### `zoneNamePublishPost(requestParameters)`
Publishes the local DNS zone to the network.
- **Parameters:** `{ name: string }`
- **Returns:** `Promise<void>`

### `configGet()` / `configPost(requestParameters)`
Manage daemon configuration.

### `commitPost()`, `publishPost()`, `publishKidPost()`, `publishManifestPost()`
Lower-level DHT publishing endpoints.

## Error Handling

When the API returns an error, the SDK will throw an exception. The error object contains the response from the server, which includes the `KIN-XXX-NNN` error code.

```typescript
try {
  const result = await publicApi.resolveNameGet({ name: 'unknown.kin' });
} catch (error) {
  // Access the error response JSON
  if (error.response) {
    const errorData = await error.response.json();
    if (errorData.code === 'KIN-RES-002') {
      console.log('Name not found!');
    } else {
      console.error('API Error:', errorData.message);
    }
  } else {
    console.error('Network Error:', error);
  }
}
```

::: warning Generated Code
The TypeScript SDK is generated automatically from the OpenAPI specification. Do not edit the generated files in the `kinetic-sdk` repository manually.
:::
