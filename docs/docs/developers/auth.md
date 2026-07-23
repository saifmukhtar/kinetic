# Authentication

The Kinetic API uses Bearer Token authentication. However, since the API is designed to run locally alongside your application, this token is a **local-only** secret. You do not need to manage internet-facing authentication or OAuth flows.

## The API Token

When the Kinetic daemon starts, it generates a unique API token and saves it to the local file system. This token is regenerated each time the daemon restarts, ensuring that only processes with read access to the local user's data directory can interact with the authenticated API endpoints.

### Token Locations

Depending on your operating system, the token is stored at the following paths:

- **Linux:** `~/.local/share/kinetic/api.token`
- **macOS:** `~/Library/Application Support/kinetic/api.token`
- **Windows:** `%APPDATA%\kinetic\api.token`

## How to Authenticate

To authenticate, you must read the token from the file system and pass it in the `Authorization` header as a Bearer token.

### Shell (curl)

```bash
TOKEN=$(cat ~/.local/share/kinetic/api.token)

curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:16002/api/owned-names
```

### TypeScript / Node.js

```typescript
import * as fs from 'fs';
import { Configuration, AuthenticatedApi } from 'kinetic-sdk';

// Read the token from the file system
const tokenPath = `${process.env.HOME}/.local/share/kinetic/api.token`;
const token = fs.readFileSync(tokenPath, 'utf8').trim();

// Pass it to the Configuration
const config = new Configuration({
  basePath: 'http://127.0.0.1:16002/api',
  accessToken: token
});

const authenticatedApi = new AuthenticatedApi(config);
```

### Rust

```rust
use std::fs;
use kinetic_sdk::apis::configuration::Configuration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read the token from the file system
    let home = std::env::var("HOME").expect("HOME not set");
    let token_path = format!("{}/.local/share/kinetic/api.token", home);
    let token = fs::read_to_string(token_path)?.trim().to_string();

    // Pass it to the Configuration
    let mut config = Configuration::new();
    config.base_path = "http://127.0.0.1:16002/api".to_string();
    config.bearer_access_token = Some(token);

    // Ready to use the authenticated API
    // let result = kinetic_sdk::apis::authenticated_api::owned_names_get(&config).await?;
    
    Ok(())
}
```

## Public vs. Authenticated Endpoints

The API is divided into two groups:

1. **Public Endpoints (No Auth Required):**
   - Resolving names (`/api/resolve/{name}`)
   - Resolving identities (`/api/resolve-kid/{did}`)
   - Fetching DNS zones (`/api/zone/{name}`)
   - Checking network status (`/api/network-status`)

2. **Authenticated Endpoints (Bearer Token Required):**
   - Registering and renewing names (`/api/vdf/...`)
   - Publishing data to the DHT (`/api/publish`, `/api/commit`)
   - Managing DNS zones (`/api/zone/...`)
   - Managing configuration (`/api/config`)
   - Listing owned names (`/api/owned-names`)

::: warning Unauthorized Errors
If you attempt to access an authenticated endpoint without a token, or with an invalid/expired token, the daemon will return an HTTP `401 Unauthorized` response. Since the token changes on restart, ensure your long-running applications reload the token if they encounter a 401.
:::
