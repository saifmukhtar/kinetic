# Example: Registering a Name

This example shows how to programmatically register a `.kin` name via the daemon API.

**Use case:** Your application is a hosting service that provisions Kinetic names for users, or you want to automate name registration from a script.

The daemon handles the full registration pipeline internally as a background task: drand fetch → VDF computation → commitment broadcast → 32-second maturation → DHT publication. Your code only needs to start the task and poll for completion.

::: danger Long running — hours, not seconds
VDF computation takes 30 minutes to several hours depending on name length. The daemon's CPU will be fully loaded for this entire time. Design your application around this — use a job queue, a webhook, or a background worker. Do not block a user-facing request thread waiting for this.
:::

::: warning One task at a time
The daemon enforces a limit of one active VDF task. Attempting to start a second returns HTTP 409. You must wait for the first to complete or fail before starting another.
:::

## TypeScript

```typescript
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Configuration, AuthenticatedApi } from '@kinetic/sdk-ts';

const tokenPath = path.join(os.homedir(), '.local', 'share', 'kinetic', 'api.token');
const token = fs.readFileSync(tokenPath, 'utf8').trim();

const config = new Configuration({
  basePath: 'http://127.0.0.1:16002/api',
  accessToken: token
});
const api = new AuthenticatedApi(config);

async function registerName(name: string): Promise<void> {
  console.log(`Starting registration for ${name}...`);

  // 1. Start the registration task in the daemon
  const { task_id } = await api.vdfRegisterPost({ vdfRegisterRequest: { name } });
  console.log(`Task started — ID: ${task_id}`);
  console.log('The daemon is now computing the VDF. This will take a while.');

  // 2. Poll every 5 minutes until done
  //    DO NOT poll every second — VDF progress is CPU-bound, not I/O-bound.
  await pollUntilDone(task_id);

  // 3. Clean up the completed task record from daemon memory
  await api.vdfStatusTaskIdDelete({ taskId: task_id });

  // 4. (Optional) Now update DNS records and publish the zone
  //    See the DNS Records example for how to do this.
  console.log(`${name} is live. Edit your zone file, then call zoneNamePublishPost.`);
}

async function pollUntilDone(taskId: string): Promise<void> {
  const POLL_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

  while (true) {
    await sleep(POLL_INTERVAL_MS);

    const task = await api.vdfStatusTaskIdGet({ taskId });

    console.log(`[${task.status}] progress: ${task.progress}%`);

    // The daemon uses exactly "Complete" (capital C) — never "completed"
    if (task.status === 'Complete') {
      console.log('Registration complete!');
      return;
    }

    if (task.status === 'Failed') {
      throw new Error(`Registration failed: ${task.error ?? 'unknown error'}`);
    }

    // Any other status means it is still running — keep polling
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Run
registerName('mycoolapp.kin').catch(console.error);
```

::: tip Status string values
The `task.status` field is a human-readable string from the daemon. The only two terminal values are:
- `"Complete"` — success, name is live on the network
- `"Failed"` — check `task.error` for the reason

All other values (`"Initializing"`, `"Computing VDF..."`, etc.) mean the task is still running.
:::

## Rust

```rust
use std::fs;
use std::time::Duration;
use tokio::time::sleep;
use kinetic_sdk::apis::configuration::Configuration;
use kinetic_sdk::apis::authenticated_api;
use kinetic_sdk::models::VdfRegisterRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read bearer token
    let home = std::env::var("HOME")?;
    let token = fs::read_to_string(format!("{}/.local/share/kinetic/api.token", home))?
        .trim()
        .to_string();

    let mut config = Configuration::new();
    config.base_path = "http://127.0.0.1:16002/api".to_string();
    config.bearer_access_token = Some(token);

    let name = "mycoolapp.kin";

    // 1. Start the registration task
    println!("Starting registration for {}...", name);
    let req = VdfRegisterRequest { name: name.to_string() };
    let task = authenticated_api::vdf_register_post(&config, req).await?;
    let task_id = task.task_id;
    println!("Task started — ID: {}", task_id);

    // 2. Poll every 5 minutes
    loop {
        sleep(Duration::from_secs(5 * 60)).await;

        let status = authenticated_api::vdf_status_task_id_get(&config, &task_id).await?;
        println!("[{}] progress: {}%", status.status, status.progress);

        // Exact string comparison — daemon uses "Complete" with capital C
        if status.status == "Complete" {
            println!("Registration complete! {} is live.", name);
            // Clean up the task record
            authenticated_api::vdf_status_task_id_delete(&config, &task_id).await?;
            break;
        }

        if status.status == "Failed" {
            let reason = status.error.unwrap_or_else(|| "unknown".to_string());
            return Err(format!("Registration failed: {}", reason).into());
        }
        // Otherwise: still running, keep polling
    }

    Ok(())
}
```

## After Registration

When the task reaches `"Complete"`, the name is registered with an empty DNS zone. To make the name actually resolve to something useful:

1. Update the DNS zone via the API (see [Publish DNS Records example](/developers/examples/publish-dns))
2. Or edit the zone file directly: `~/.local/share/kinetic/zones/mycoolapp.kin.json`
3. Then call `zoneNamePublishPost` to push the updated zone to the DHT

## Application Design Notes

Because registration takes hours, do not build a synchronous flow around it. Instead:

- **Store the `task_id`** in a database when you start registration
- **Background worker** polls the status periodically and updates the record when done
- **Notify the user** via email, webhook, or push when the name is live
- **Limit one active registration per daemon** — if you need to register many names, queue them and process one at a time
