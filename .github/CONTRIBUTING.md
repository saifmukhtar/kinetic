# Contributing to Kinetic

Thank you for your interest in contributing to the Kinetic Protocol! We are building a mathematically secured, decentralized networking stack in Rust, and we welcome contributions from the community.

## 1. How to Contribute

There are many ways to contribute to Kinetic:
- **Core Rust Development:** Fixing bugs, optimizing the VDF engine, or enhancing the Kademlia DHT logic.
- **Documentation:** Improving the mdBook, writing tutorials, or updating the IETF Internet-Drafts.
- **Testing:** Writing end-to-end tests for the DHT swarm or finding edge cases in the deterministic XOR tie-breaker.
- **UI/UX:** Enhancing the embedded `kinetic-ui` React frontend or the Flutter `kinetic-client`.

## 2. Reporting Issues

If you find a bug or have a feature request, please open an issue on GitHub.
- **Bug Reports:** Include steps to reproduce, the OS/Environment, and any relevant panic logs or error messages.
- **Security Vulnerabilities:** **DO NOT open a public issue.** Please refer to `SECURITY.md` for responsible disclosure instructions.

## 3. Pull Request Requirements

Kinetic enforces a high standard for code quality and cryptographic security. To ensure your Pull Request is merged smoothly, it **must** meet the following strict technical requirements:

### A. Code Formatting and Linting
All Rust code must be formatted using the standard Rust toolchain.
```bash
cargo fmt --all -- --check
```

All code must pass Clippy lints without warnings. We do not accept code with unhandled `unwrap()` calls in critical network or VDF paths unless explicitly justified.
```bash
cargo clippy --workspace --all-targets -- -D warnings
```

### B. Testing
All existing and new tests must pass. If you add a new feature, you must add corresponding unit or integration tests.
```bash
cargo test --workspace
```

### C. Signed Commits (GPG/SSH)
To protect against supply-chain attacks, **all commits in your Pull Request must be cryptographically signed**. We accept GPG, SSH, or S/MIME signatures. Commits that are not "Verified" by GitHub will not be merged.

To configure commit signing, refer to the [GitHub Documentation on Commit Signature Verification](https://docs.github.com/en/authentication/managing-commit-signature-verification).

## 4. The Pull Request Workflow

1. Fork the repository and create your branch from `main`.
2. Write your code, ensuring you follow the rules above (`fmt`, `clippy`, `test`).
3. Ensure your commits are signed.
4. Open a Pull Request. Provide a detailed description of what you changed, why you changed it, and any testing you performed.
5. A core maintainer will review your code. We may request changes or ask clarifying questions regarding performance or security implications.
6. Once approved, your code will be merged into `main`!

By contributing to Kinetic, you agree that your contributions will be licensed under the project's Apache 2.0 license.
