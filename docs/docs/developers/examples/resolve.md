# Example: Resolving a Name

This example demonstrates how to resolve a `.kin` name to find its IP address using the Public API.

**Use Case:** You are building an application that allows users to connect to servers using decentralized `.kin` names instead of IP addresses.

::: tip Caching
In a production app, you should cache the resolved IP addresses to avoid hitting the local daemon on every request. Follow standard DNS TTL principles.
:::

## TypeScript Example

```typescript
import { Configuration, PublicApi } from 'kinetic-sdk';

async function resolveIpAddress(name: string): Promise<string | null> {
  const config = new Configuration({ basePath: 'http://127.0.0.1:16002/api' });
  const api = new PublicApi(config);

  try {
    // 1. Fetch the DNS zone directly
    const zone = await api.zoneNameGet({ name });
    
    // 2. Extract the A records at the apex (@)
    if (zone.records && zone.records['@']) {
      const aRecords = zone.records['@'].filter(r => r.type === 'A');
      if (aRecords.length > 0) {
        return aRecords[0].value;
      }
    }
    
    return null; // No A record found
    
  } catch (error: any) {
    if (error.response) {
      const errorData = await error.response.json();
      if (errorData.code === 'KIN-RES-002') {
        console.log(`Domain ${name} not found.`);
      } else if (errorData.code === 'KIN-RES-001') {
        console.error('Kinetic daemon is offline from the DHT network.');
      } else {
        console.error('API Error:', errorData.message);
      }
    } else {
      console.error('Network Error:', error.message);
    }
    return null;
  }
}

// Usage:
resolveIpAddress('alice.kin').then(ip => console.log('Resolved IP:', ip));
```

## Rust Example

```rust
use kinetic_sdk::apis::configuration::Configuration;
use kinetic_sdk::apis::public_api;
use kinetic_sdk::apis::Error;

async fn resolve_ip_address(name: &str) -> Option<String> {
    let mut config = Configuration::new();
    config.base_path = "http://127.0.0.1:16002/api".to_string();

    match public_api::zone_name_get(&config, name).await {
        Ok(zone) => {
            if let Some(records_map) = zone.records {
                if let Some(apex_records) = records_map.get("@") {
                    for record in apex_records {
                        if record.r#type == "A" {
                            return Some(record.value.clone());
                        }
                    }
                }
            }
            None
        }
        Err(Error::ResponseError(err)) => {
            if err.status == reqwest::StatusCode::NOT_FOUND {
                println!("Domain {} not found.", name);
            } else {
                println!("API Error: {}", err.content);
            }
            None
        }
        Err(e) => {
            println!("Network Error: {:?}", e);
            None
        }
    }
}

#[tokio::main]
async fn main() {
    if let Some(ip) = resolve_ip_address("alice.kin").await {
        println!("Resolved IP: {}", ip);
    }
}
```
