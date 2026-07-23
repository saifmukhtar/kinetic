# Example: Registering a Name

This example demonstrates how to programmatically register a `.kin` name using the Authenticated API.

**Use Case:** Your application acts as a registrar or hosting service that automatically provisions Kinetic names for your users.

::: danger Long Running Process
Name registration in Kinetic requires computing a Verifiable Delay Function (VDF), which guarantees sequential time has passed. This process takes anywhere from 30 minutes to several hours depending on the name's length. **Do not block your main application thread while waiting for this to complete.** You must poll the status asynchronously.
:::

## TypeScript Example

```typescript
import * as fs from 'fs';
import { Configuration, AuthenticatedApi } from 'kinetic-sdk';

const token = fs.readFileSync(`${process.env.HOME}/.local/share/kinetic/api.token`, 'utf8').trim();
const config = new Configuration({ basePath: 'http://127.0.0.1:16002/api', accessToken: token });
const api = new AuthenticatedApi(config);

async function registerName(name: string) {
  try {
    // 1. Start the registration task
    console.log(`Starting registration for ${name}...`);
    const { task_id } = await api.vdfRegisterPost({ vdfRegisterRequest: { name } });
    console.log(`Task started with ID: ${task_id}`);

    // 2. Poll status periodically (every 5 minutes)
    const intervalId = setInterval(async () => {
      try {
        const status = await api.vdfStatusTaskIdGet({ taskId: task_id });
        console.log(`Progress: ${status.progress} / ${status.iterations}`);

        if (status.status === 'completed') {
          clearInterval(intervalId);
          console.log(`Registration for ${name} completed successfully!`);
          
          // 3. Clean up the task
          await api.vdfStatusTaskIdDelete({ taskId: task_id });
          console.log('Task cleaned up.');
          
          // Next step: Set up DNS and publish zone (see DNS example)
        } else if (status.status === 'failed') {
          clearInterval(intervalId);
          console.error(`Registration failed: ${status.error}`);
          await api.vdfStatusTaskIdDelete({ taskId: task_id });
        }
      } catch (err) {
        console.error('Error polling status', err);
      }
    }, 5 * 60 * 1000); // 5 minutes

  } catch (error) {
    console.error('Failed to start registration', error);
  }
}

registerName('mycoolapp.kin');
```

::: warning Polling Frequency
Because the VDF is highly CPU-bound and deliberately slow, its progress does not jump rapidly. **Do not poll more than once per minute.** Polling every 5 minutes is recommended.
:::

## Rust Example

```rust
use std::fs;
use std::time::Duration;
use tokio::time::sleep;
use kinetic_sdk::apis::configuration::Configuration;
use kinetic_sdk::apis::authenticated_api;
use kinetic_sdk::models::VdfRegisterRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = fs::read_to_string(format!("{}/.local/share/kinetic/api.token", std::env::var("HOME")?))?.trim().to_string();
    let mut config = Configuration::new();
    config.base_path = "http://127.0.0.1:16002/api".to_string();
    config.bearer_access_token = Some(token);

    let name = "mycoolapp.kin";
    
    println!("Starting registration for {}...", name);
    let req = VdfRegisterRequest { name: name.to_string() };
    let task = authenticated_api::vdf_register_post(&config, req).await?;
    let task_id = task.task_id;
    println!("Task started with ID: {}", task_id);

    loop {
        sleep(Duration::from_secs(5 * 60)).await; // Wait 5 minutes

        let status = authenticated_api::vdf_status_task_id_get(&config, &task_id).await?;
        println!("Progress: {} / {}", status.progress, status.iterations);

        if status.status == "completed" {
            println!("Registration completed successfully!");
            authenticated_api::vdf_status_task_id_delete(&config, &task_id).await?;
            break;
        } else if status.status == "failed" {
            println!("Registration failed: {:?}", status.error);
            authenticated_api::vdf_status_task_id_delete(&config, &task_id).await?;
            break;
        }
    }

    Ok(())
}
```
