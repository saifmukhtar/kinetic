# Rust SDK

The Kinetic Rust SDK provides a strongly-typed, asynchronous client for the Kinetic REST API. It is generated from our OpenAPI specifications and utilizes the `tokio` async runtime and `reqwest` HTTP client.

## Installation

Add the SDK to your `Cargo.toml`. Since it is published on crates.io, you can add it as a standard dependency:

```toml
[dependencies]
kinetic-sdk = "0.1.1"
tokio = { version = "1", features = ["full"] }
```

## Initialization & Authentication

The SDK exposes methods under `kinetic_sdk::apis::public_api` and `kinetic_sdk::apis::authenticated_api`. Both require passing a reference to a `Configuration` struct.

To use the authenticated methods, you must populate the `bearer_access_token` field in the configuration.

```rust
use std::fs;
use kinetic_sdk::apis::configuration::Configuration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Read token from file
    let home = std::env::var("HOME").expect("HOME not set");
    let token_path = format!("{}/.local/share/kinetic/api.token", home);
    let token = fs::read_to_string(token_path)?.trim().to_string();

    // 2. Setup Configuration
    let mut config = Configuration::new();
    config.base_path = "http://127.0.0.1:16002/api".to_string();
    config.bearer_access_token = Some(token);

    // Now you can pass `&config` to API methods
    
    Ok(())
}
```

## Key API Methods

### Public API

```rust
use kinetic_sdk::apis::public_api;

// Resolve a name
let name_result = public_api::resolve_name_get(&config, "alice.kin").await?;
println!("Resolved: {:?}", name_result);

// Fetch DNS zone
let zone_result = public_api::zone_name_get(&config, "alice.kin").await?;
println!("Zone records: {:?}", zone_result.records);
```

### Authenticated API

```rust
use kinetic_sdk::apis::authenticated_api;
use kinetic_sdk::models::{VdfRegisterRequest, DnsZone};

// List owned names
let names = authenticated_api::owned_names_get(&config).await?;
println!("Owned names: {:?}", names);

// Start VDF registration
let req = VdfRegisterRequest { name: "bob.kin".to_string() };
let task = authenticated_api::vdf_register_post(&config, req).await?;
println!("Task ID: {}", task.task_id);

// Check VDF status
let status = authenticated_api::vdf_status_task_id_get(&config, &task.task_id).await?;
println!("Status: {}", status.status);

// Publish DNS zone
authenticated_api::zone_name_publish_post(&config, "bob.kin").await?;
```

## Error Handling

API methods return a `Result<T, Error<E>>`, where `Error` is defined in the SDK and `E` is a specific error enum for that endpoint (e.g., `ResolveNameGetError`). 

When the API returns an error response (like a 404), you can match on it to handle it gracefully:

```rust
use kinetic_sdk::apis::public_api;
use kinetic_sdk::apis::Error;

match public_api::resolve_name_get(&config, "unknown.kin").await {
    Ok(reveal) => {
        println!("Found!");
    }
    Err(Error::ResponseError(err)) => {
        if err.status == reqwest::StatusCode::NOT_FOUND {
            println!("Name is not registered.");
        } else {
            println!("API Error: {}", err.content);
        }
    }
    Err(e) => {
        println!("Network or parse error: {:?}", e);
    }
}
```

::: tip Async Runtime
The SDK requires an async runtime to execute HTTP requests. Ensure you use `#[tokio::main]` or execute the futures within a Tokio context.
:::
