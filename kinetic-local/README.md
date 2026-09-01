# Kinetic Local

Local node management, OS integration, and secure credential storage for the Kinetic Network.

## Architecture

While `kinetic-core` contains the pure logic of the network, `kinetic-local` bridges that logic with the host Operating System. It is strictly responsible for managing state that persists on the local disk.

**Key Responsibilities:**
- **Secure Identity Storage:** Uses AES-GCM, PBKDF2, and BIP39 mnemonics to encrypt and store the user's ML-DSA-65 private keys securely on disk (`~/.kinetic/`).
- **Configuration Management:** Parses and manages the local `config.toml` file.
- **State Persistence:** Atomically writes and reads the global governance state using fast binary (`bincode`) serialization and temporary files to prevent corruption.
- **Process Lifecycle:** Traps OS signals (like `SIGINT` via `Ctrl-C`) using `tokio` to gracefully shut down the daemon.
