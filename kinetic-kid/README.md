# Kinetic Identity Document (KID)

`kinetic-kid` is a pure mathematical sandbox crate for parsing, signing, and verifying JSON-formatted Kinetic Identity Documents.

## Core Philosophy

This crate adheres to the strict **Compiler-Enforced Sandbox Philosophy**.
It is completely decoupled from async runtimes (`tokio`), disk I/O, and the local operating system clock. It only performs pure state transitions and cryptographic math.

## Time Verification Architecture

Because `kinetic-kid` cannot access the system clock (to prevent non-deterministic consensus failures), time must be explicitly injected into verification functions like `verify_at_time(doc, unix_time)`.

In client or WebAssembly (WASM) environments, there are two ways to handle time injection:

### 1. The Secure Way (Recommended)
Fetch the latest **VDF (Verifiable Delay Function) proof** from the Kinetic network. Because VDF verification is extremely fast, you can prove the current network time (`Kyn`) locally in WASM with absolute mathematical certainty. 

Once verified, derive the Unix timestamp and pass it to the verification function. This completely eliminates the risk of a user tampering with their local device clock to bypass document expiration dates.

### 2. The Simple Way (Insecure / Offline)
If you only need an offline wall-clock check, the outer environment (e.g., JavaScript/TypeScript) can fetch the time and pass it in:

```typescript
// Fetch the time securely from the outer JS shell
const currentTime = Math.floor(Date.now() / 1000);
wasm.verify_at_time(doc, currentTime);
```
*Note: This is vulnerable to local time manipulation (e.g., a user changing their calendar).*

## Cryptography
All cryptographic operations (SHA-256 and ML-DSA-65) are securely inherited from the highly isolated `kinetic-primitives` crate.
