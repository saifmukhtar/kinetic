# Example: Managing DNS Records

This example demonstrates how to programmatically update and publish DNS records for a `.kin` name you already own.

**Use Case:** You are migrating your application to a new server and need to update the `A` record automatically via a script, or you are managing a fleet of domains programmatically.

::: tip Limits
Kinetic DNS zones support a maximum of 50 records in total. `TXT` records have a strict size limit of 255 bytes per record.
:::

## TypeScript Example

```typescript
import * as fs from 'fs';
import { Configuration, AuthenticatedApi } from '@kinetic/sdk-ts';

const token = fs.readFileSync(`${process.env.HOME}/.local/share/kinetic/api.token`, 'utf8').trim();
const config = new Configuration({ basePath: 'http://127.0.0.1:16002/api', accessToken: token });
const api = new AuthenticatedApi(config);

async function updateIPAddress(name: string, newIp: string) {
  try {
    // 1. Fetch current local zone
    // Note: If you just registered the name, the zone might be empty or 404, handle accordingly.
    let zone;
    try {
      zone = await api.zoneNameGet({ name });
    } catch (e) {
      zone = { records: {} }; // Initialize empty zone if none exists
    }

    if (!zone.records) zone.records = {};
    if (!zone.records['@']) zone.records['@'] = [];

    // 2. Remove old A records at apex
    zone.records['@'] = zone.records['@'].filter(r => r.type !== 'A');

    // 3. Add the new A record
    zone.records['@'].push({ type: 'A', value: newIp });

    // 4. Save the updated zone locally
    console.log(`Saving updated zone for ${name}...`);
    await api.zoneNamePost({ name, dnsZone: zone });

    // 5. Publish the cryptographically signed zone to the DHT
    console.log(`Publishing zone to the network...`);
    await api.zoneNamePublishPost({ name });

    console.log(`Successfully updated ${name} to point to ${newIp}`);
  } catch (error: any) {
    console.error('Error updating DNS', error.response ? await error.response.json() : error);
  }
}

updateIPAddress('alice.kin', '203.0.113.50');
```

## Rust Example

```rust
use std::fs;
use std::collections::HashMap;
use kinetic_sdk::apis::configuration::Configuration;
use kinetic_sdk::apis::authenticated_api;
use kinetic_sdk::models::{DnsZone, Record};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = fs::read_to_string(format!("{}/.local/share/kinetic/api.token", std::env::var("HOME")?))?.trim().to_string();
    let mut config = Configuration::new();
    config.base_path = "http://127.0.0.1:16002/api".to_string();
    config.bearer_access_token = Some(token);

    let name = "alice.kin";
    let new_ip = "203.0.113.50".to_string();

    // 1. Fetch current zone (or create new if missing)
    let mut zone = authenticated_api::zone_name_get(&config, name).await.unwrap_or_else(|_| {
        DnsZone { records: Some(HashMap::new()) }
    });

    let mut records_map = zone.records.unwrap_or_else(HashMap::new);
    let mut apex_records = records_map.remove("@").unwrap_or_else(Vec::new);

    // 2. Remove old A records
    apex_records.retain(|r| r.r#type != "A");

    // 3. Add new A record
    apex_records.push(Record {
        r#type: "A".to_string(),
        value: new_ip.clone(),
    });

    records_map.insert("@".to_string(), apex_records);
    zone.records = Some(records_map);

    // 4. Save locally
    println!("Saving updated zone for {}...", name);
    authenticated_api::zone_name_post(&config, name, zone).await?;

    // 5. Publish to DHT
    println!("Publishing zone to the network...");
    authenticated_api::zone_name_publish_post(&config, name).await?;

    println!("Successfully updated {} to point to {}", name, new_ip);

    Ok(())
}
```
