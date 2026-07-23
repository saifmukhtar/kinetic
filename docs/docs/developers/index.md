# Developer Overview

Welcome to the Kinetic Developer Documentation. Kinetic provides a decentralized naming and identity system built on a DHT and cryptographic proofs. As a developer, you can integrate Kinetic to build powerful applications on top of this infrastructure.

## What You Can Build

- **Name Resolvers:** Build applications that resolve `.kin` names to IP addresses or other records, just like traditional DNS but fully decentralized.
- **Programmatic Registration:** Automate the provisioning of `.kin` names for your users directly from your application.
- **DNS Management:** Programmatically update DNS zones and publish them to the network.
- **Identity Lookups:** Resolve `KID` (Kinetic Identity Document) profiles using standard `did:kin:...` identifiers.

## Prerequisites

To interact with the Kinetic network, you need to run a Kinetic daemon locally. The API is exposed by the daemon.

```bash
sudo kinetic daemon
```

By default, the daemon exposes its REST API at `http://127.0.0.1:16002/api`.

## SDKs and API

We provide SDKs generated from our OpenAPI specification, as well as the raw REST API for direct interaction.

1. **[TypeScript SDK](./sdk-typescript.md):** Best for Node.js, web apps, and scripts.
2. **[Rust SDK](./sdk-rust.md):** Best for high-performance systems and native integrations.
3. **[REST API](./api/index.md):** For custom integrations using standard HTTP clients.

## Quick Start: Hello World

Here's a 5-line example in TypeScript that resolves a `.kin` name and prints the result.

```typescript
import { Configuration, PublicApi } from 'kinetic-sdk';

const api = new PublicApi(new Configuration({ basePath: 'http://127.0.0.1:16002/api' }));
const result = await api.resolveNameGet({ name: 'hello.kin' });
console.log('Resolved:', result);
```

To access authenticated endpoints (like registering a name or publishing DNS records), you'll need the daemon's API token. 

👉 **[Read the Authentication Guide](./auth.md) next to learn how to authenticate your requests.**
