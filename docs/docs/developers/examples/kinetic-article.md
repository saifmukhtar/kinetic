# Building `kinetic-article`

The `kinetic-article` repository is the official reference implementation for building a decentralized web application on top of the Kinetic network. It demonstrates how to use the Kinetic TypeScript SDK in a modern React application.

## 1. What We Are Building

`kinetic-article` is an unstoppable, decentralized publishing platform. 

Normally, when you write an article, you publish it to a centralized platform like Medium, Substack, or Twitter. With Kinetic, you own your namespace cryptographically. This application allows an author to write an article in markdown and publish it *directly* to their `.kin` domain on the local DHT network. 

Because Kinetic runs a local DNS proxy, anyone on the network can resolve your `.kin` name and read your article, entirely peer-to-peer, with zero hosting costs and zero middlemen.

## 2. Adding the SDK

The application is built using React 19, TypeScript, Vite, and Tailwind CSS. To connect this frontend to the Kinetic network, we install the official TypeScript SDK.

The SDK is published on npm. Install it directly into your project:

```bash
npm install @kinetic-sdk/ts
```

## 3. Wiring up the SDK

The SDK provides a strongly-typed client generated from the Kinetic OpenAPI specification. We need to initialize the API clients (`PublicApi` and `PrivateApi`) and provide them to our React component tree.

### The Vite Proxy (Authentication)

The `PrivateApi` requires a Bearer token to communicate securely with your local Kinetic Daemon. However, browser environments cannot read the token from your filesystem (`~/.local/share/kinetic/api.token`). 

To solve this, `kinetic-article` uses a Vite server proxy. The frontend sends requests to `/api/*`, and Vite intercepts them, attaches the token from the filesystem, and proxies the request to the local daemon (running on port `16002`).

In `vite.config.ts`:

```typescript
import { defineConfig } from 'vitest/config';
import fs from 'fs';
import os from 'os';
import path from 'path';

function getToken() {
  const tokenPath = path.join(os.homedir(), '.local', 'share', 'kinetic', 'api.token');
  return fs.readFileSync(tokenPath, 'utf8').trim();
}

export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:16002',
        changeOrigin: true,
        headers: {
          'Authorization': `Bearer ${getToken()}`
        }
      }
    }
  }
});
```

### The React Provider

Now that the proxy handles authentication, wiring up the SDK in React is incredibly simple. We create a Context Provider in `src/KineticProvider.tsx`:

```tsx
import React, { createContext, useContext } from 'react';
import { PublicApi, PrivateApi, Configuration } from '@kinetic-sdk/ts';

interface KineticContextType {
  publicApi: PublicApi;
  privateApi: PrivateApi;
}

const KineticContext = createContext<KineticContextType | undefined>(undefined);

export const KineticProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // We use an empty basePath to let requests fall through to the Vite proxy
  const config = new Configuration({
    basePath: '' 
  });

  const publicApi = new PublicApi(config);
  const privateApi = new PrivateApi(config);

  return (
    <KineticContext.Provider value={{ publicApi, privateApi }}>
      {children}
    </KineticContext.Provider>
  );
};

export const useKinetic = () => {
  const context = useContext(KineticContext);
  if (!context) throw new Error('useKinetic must be used within a KineticProvider');
  return context;
};
```

### Using the SDK in Components

Any component can now use the `useKinetic` hook to interact with the network. For example, resolving a name:

```tsx
import { useKinetic } from './KineticProvider';

export function ResolveButton() {
  const { publicApi } = useKinetic();

  const handleResolve = async () => {
    try {
      const reveal = await publicApi.resolveNameGet({ name: 'alice.kin' });
      console.log('Successfully resolved:', reveal);
    } catch (error) {
      console.error('Failed to resolve name');
    }
  };

  return <button onClick={handleResolve}>Resolve alice.kin</button>;
}
```

This architecture completely decouples your frontend code from the complexities of the Kinetic daemon, allowing you to build decentralized apps as easily as traditional web apps!
