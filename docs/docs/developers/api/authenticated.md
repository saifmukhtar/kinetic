# Authenticated API

These endpoints require the `Authorization: Bearer <token>` header. They are used for managing names, identities, DNS zones, and daemon configuration.

::: tip Getting the Token
See the [Authentication](/developers/auth) guide for details on where to find the local API token.
:::

## 1. Commit Name Hash
**POST** `/api/commit`

Commits a name hash to the DHT. This is part of the manual registration flow (usually handled automatically by the VDF task).

**Request Body:**
```json
{
  "name": "alice.kin",
  "commitment": {
    "hash": [ ... bytes ... ]
  }
}
```

**Example Request:**
```bash
curl -X POST http://127.0.0.1:16002/api/commit \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"alice.kin","commitment":{"hash":[]}}'
```

**Example Response:**
```json
{
  "success": true
}
```

**Possible Errors:**
- `KIN-REQ-001`: Invalid request format.

## 2. Publish Reveal
**POST** `/api/publish`

Publishes a name Reveal to the DHT to finalize registration or update data.

**Request Body:**
```json
{
  "reveal": {
    "name": "alice.kin",
    "pubkey": [...],
    "drand_pulse": 839485,
    "iterations": 5000000,
    "vdf_proof": "...",
    "signature": "...",
    "payload": "..."
  }
}
```

**Example Response:**
```json
{
  "success": true
}
```

## 3. Publish KID
**POST** `/api/publish-kid`

Publishes a signed KID identity document to the network.

**Request Body:**
```json
{
  "authorized_kid": { ... }
}
```

## 4. Publish Manifest
**POST** `/api/publish-manifest`

Publishes a Capability Manifest associated with a KID.

**Request Body:**
```json
{
  "authorized_manifest": { ... }
}
```

## 5. Get Configuration
**GET** `/api/config`

Retrieves the current daemon configuration.

**Example Response:**
```json
{
  "mode": "light",
  "data_dir": "/home/user/.local/share/kinetic"
}
```

## 6. Update Configuration
**POST** `/api/config`

Updates daemon configuration settings dynamically.

**Request Body:**
```json
{
  "mode": "light"
}
```

## 7. List Owned Names
**GET** `/api/owned-names`

Returns an array of all names owned by the local daemon.

**Example Response:**
```json
[
  "alice.kin",
  "bob.kin"
]
```

## 8. Start VDF Registration
**POST** `/api/vdf/register`

Starts a background task to compute the VDF for a new name registration. This handles commit, wait, and reveal automatically.

**Request Body:**
```json
{
  "name": "alice.kin"
}
```

**Example Response:**
```json
{
  "task_id": "task_abc123",
  "message": "Task started successfully."
}
```

## 9. Start VDF Renewal
**POST** `/api/vdf/renew`

Starts a background task to renew an existing name.

**Request Body:**
```json
{
  "name": "alice.kin"
}
```

## 10. Get VDF Task Status
**GET** `/api/vdf/status/{task_id}`

Retrieves the current progress of a VDF task.

**Example Response:**
```json
{
  "status": "running",
  "iterations": 5000000,
  "progress": 2500000,
  "error": null
}
```

**Statuses:** `running`, `completed`, `failed`.

## 11. Delete VDF Task
**DELETE** `/api/vdf/status/{task_id}`

Cancels a running VDF task or cleans up the state of a completed/failed task.

**Example Response:**
```json
{
  "success": true
}
```

## 12. Get Local DNS Zone
**GET** `/api/zone/{name}`

Same output format as the public endpoint, but reads directly from local storage for owned names before they are published.

## 13. Update Local DNS Zone
**POST** `/api/zone/{name}`

Saves or updates a local DNS zone file. Does not publish it to the network.

**Request Body:**
```json
{
  "records": {
    "@": [
      { "type": "A", "value": "192.168.1.100" }
    ]
  }
}
```

## 14. Publish DNS Zone
**POST** `/api/zone/{name}/publish`

Cryptographically signs the local DNS zone file and publishes it to the DHT, making it live on the network.

**Example Request:**
```bash
curl -X POST http://127.0.0.1:16002/api/zone/alice.kin/publish \
  -H "Authorization: Bearer $TOKEN"
```
