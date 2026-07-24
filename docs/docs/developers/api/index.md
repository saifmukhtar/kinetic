# REST API Overview

The Kinetic daemon exposes a local REST API that you can interact with using standard HTTP requests.

- **Base URL:** `http://127.0.0.1:16002/api`
- **Content-Type:** `application/json` (for all request bodies and responses)
- **Authentication:** Bearer token (see [Authentication](/developers/auth) for details).

## Endpoints Summary

### Public Endpoints
No authentication is required for these endpoints.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/network-status` | Returns the current network connectivity status. |
| GET | `/api/resolve/{name}` | Resolves a Kinetic name and returns the Reveal object. |
| GET | `/api/resolve-kid/{did}`| Resolves a KID identity (`did:kin:...`). |
| GET | `/api/zone/{name}` | Returns the DNS zone for a given name. |

### Authenticated Endpoints
Requires `Authorization: Bearer <token>` header.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/commit` | Commits a name hash to the DHT. |
| POST | `/api/publish` | Publishes a name reveal to the DHT. |
| POST | `/api/publish-kid` | Publishes a KID identity document. |
| POST | `/api/publish-manifest` | Publishes a Capability Manifest. |
| GET | `/api/config` | Retrieves the daemon configuration. |
| POST | `/api/config` | Updates the daemon configuration. |
| GET | `/api/owned-names` | Lists all locally owned names. |
| POST | `/api/vdf/register` | Starts a VDF name registration task. |
| POST | `/api/vdf/renew` | Starts a VDF name renewal task. |
| GET | `/api/vdf/status/{task_id}`| Gets the status of a running VDF task. |
| DELETE | `/api/vdf/status/{task_id}`| Cancels/deletes a VDF task. |
| GET | `/api/zone/{name}` | Retrieves the local DNS zone for an owned name. |
| POST | `/api/zone/{name}` | Saves/updates a local DNS zone file. |
| POST | `/api/zone/{name}/publish`| Signs and publishes a zone to the DHT. |

## Error Format

When an API request fails, it returns a standard JSON error response conforming to RFC 7807. The HTTP status code will reflect the error type (e.g., `404 Not Found`, `400 Bad Request`), and the body will contain a machine-readable `code` and a human-readable `message`.

```json
{
  "code": "KIN-RES-002",
  "message": "The domain is not registered on the Kinetic network.",
  "status": 404
}
```

You can programmatically match on the `code` field to handle specific error conditions.

## Pagination & Rate Limiting

- **Pagination:** There is currently no pagination. List endpoints (like `/api/owned-names`) return the full collection in a single response.
- **Rate Limiting:** Because this is a local-only API, there are no strict rate limits. However, VDF polling should be kept to reasonable intervals (e.g., once every 1-5 minutes) to avoid unnecessary overhead.
