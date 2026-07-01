# Kinetic Project Governance

This document describes the governance model for the Kinetic Protocol, detailing how decisions are made, how maintainers are appointed, and how releases are managed. As the project matures from a single-author system into a broader open-source standard, this governance model ensures that Kinetic remains decentralized, mathematically rigorous, and secure.

## 1. Decision Making (Consensus Model)

Kinetic uses a **Consensus Model** for major architectural decisions, protocol upgrades, and IETF draft modifications.

- **Routine Changes:** Minor bug fixes, documentation updates, and standard refactoring can be merged by any core maintainer.
- **Architectural Changes:** For significant changes (e.g., modifying the VDF parameters, altering the Kademlia DHT routing logic, or changing the payload size limits), decisions are made by a **vote among the core group of maintainers**.
- **The RFC Process:** Significant changes must be proposed via an RFC (Request for Comments) issue on GitHub. The core team will review the proposal, and consensus must be reached before the change is implemented and merged.

## 2. Project Roles

### Core Maintainers
Core maintainers have write access to the repository, merge privileges for Pull Requests, and voting rights on architectural changes.

### Adding New Maintainers (Meritocracy)
Maintainership is granted through a strict **merit-based appointment** process. Contributors are invited to become maintainers by the Lead Maintainer (Saif Mukhtar) or the existing core team after demonstrating:
- Sustained, high-quality code contributions over a period of 3-6 months.
- Active participation in code reviews for other contributors' PRs.
- Constructive participation in protocol discussions (e.g., GitHub Issues, IETF draft discussions).
- A deep understanding of the cryptographic and P2P networking principles underlying Kinetic.

## 3. Release Process

While architectural decisions are made by consensus, the logistics of releasing the software are currently centralized to ensure cryptographic supply-chain security.

- **Schedule & Tagging:** The Lead Maintainer (Saif Mukhtar) is responsible for determining the release schedule, evaluating stability, and cutting release tags.
- **Publishing:** Only the Lead Maintainer has the authorization to publish official `kinetic-core`, `kinetic-vdf`, `kinetic-daemon`, and `kinetic-cli` crates to `crates.io`.
- **Binaries:** Official compiled binaries for macOS, Linux, and Windows are signed and attached to GitHub Releases by the Lead Maintainer.
