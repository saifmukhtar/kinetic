# Public API

These endpoints do not require authentication. They are used for querying the Kinetic network state, resolving names, and fetching public data.

## 1. Network Status
**GET** `/api/network-status`

Returns the current connectivity status of the Kinetic daemon to the peer-to-peer network.

**Example Request:**
```bash
curl http://127.0.0.1:16002/api/network-status
```

**Example Response:**
```json
{
  "status": "connected",
  "peers": 42
}
```

## 2. Resolve Name
**GET** `/api/resolve/{name}`

Resolves a Kinetic name (e.g., `alice.kin`) and returns its Reveal object containing the cryptographic proofs and the embedded DNS payload.

**Parameters:**
- `name` (path parameter): The name to resolve.

**Example Request:**
```bash
curl http://127.0.0.1:16002/api/resolve/alice.kin
```

**Example Response:**
```json
{
  "name": "alice.kin",
  "pubkey": [12, 54, 21, ...],
  "drand_pulse": 839485,
  "iterations": 5000000,
  "vdf_proof": "base64encodedproof...",
  "signature": "base64encodedsignature...",
  "payload": "base64encodeddnszone..."
}
```

### The Reveal Object Fields
- `name`: The registered name.
- `pubkey`: The Ed25519 public key bytes controlling this name.
- `drand_pulse`: The round of randomness used as the VDF seed.
- `iterations`: The VDF difficulty (number of sequential operations required).
- `vdf_proof`: The proof that the VDF was computed correctly.
- `signature`: Cryptographic signature verifying the payload.
- `payload`: The serialized DNS zone data.

**Possible Errors:**
- `KIN-RES-001`: Network offline.
- `KIN-RES-002`: Domain not registered.

## 3. Resolve KID
**GET** `/api/resolve-kid/{did}`

Resolves a Kinetic Identity Document (KID) using its DID representation (`did:kin:...`). Returns the KID document and its associated capability manifest.

**Parameters:**
- `did` (path parameter): The DID string.

**Example Request:**
```bash
curl http://127.0.0.1:16002/api/resolve-kid/did:kin:abc123def456
```

**Example Response:**
```json
{
  "kid_document": {
    "id": "did:kin:abc123def456",
    "verificationMethod": [...]
  },
  "manifest_document": {
    "capabilities": [...]
  }
}
```

**Possible Errors:**
- `KIN-RES-001`: Network offline.
- `KIN-RES-002`: Identity not found.

## 4. Get DNS Zone
**GET** `/api/zone/{name}`

Returns the parsed DNS zone for a given name, extracted from its Reveal payload.

**Parameters:**
- `name` (path parameter): The name to query.

**Example Request:**
```bash
curl http://127.0.0.1:16002/api/zone/alice.kin
```

**Example Response:**
```json
{
  "records": {
    "@": [
      {
        "type": "A",
        "value": "192.168.1.100"
      },
      {
        "type": "TXT",
        "value": "hello world"
      }
    ],
    "www": [
      {
        "type": "CNAME",
        "value": "alice.kin"
      }
    ]
  }
}
```

**Possible Errors:**
- `KIN-RES-001`: Network offline.
- `KIN-RES-002`: Domain not registered.
- `KIN-ZON-001`: Invalid zone payload format.
