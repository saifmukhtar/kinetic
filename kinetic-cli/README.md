# kinetic-cli

## 1. Overview
`kinetic-cli` is the stateless command-line interface for the Kinetic network. It allows developers and power users to interact with their locally running `kinetic-daemon`.

## 2. Architecture & Responsibilities
This crate is built entirely around `clap` and `reqwest`. 
When a user types `kinetic name register myname`, the CLI:
1. Parses the arguments via `clap`.
2. Reads the authentication token from `~/.local/share/kinetic/api.token`.
3. Constructs a JSON payload.
4. Executes a `POST` request to `http://127.0.0.1:16001/api/v1/name/register`.
5. Formats the JSON response into human-readable terminal output.

## 3. Reading Guide
- `src/main.rs`: The main `clap` router and entry point.
- `src/commands/`: Contains a subdirectory for each major subcommand (e.g., `name`, `network`, `system`, `identity`).
- `src/utils.rs`: Contains the HTTP client wrapper that injects the `X-Kinetic-Token` header.

## 4. Taxonomy
This crate is a **Layer 9 Executable**. See [`./LAYER_9.md`](./LAYER_9.md) for architectural constraints.
