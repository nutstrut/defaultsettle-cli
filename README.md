# Default Settlement CLI

Default Settlement is machine trust infrastructure for autonomous systems.

This repository contains the v0.1 scaffold for the developer command-line entry
point. The CLI will allow developers to activate agents, verify evidence,
inspect chains, and retrieve public trust profiles.

## Lifecycle

Agent Activation
-> SAR Verification
-> Continuity Verification
-> Chained Evidence
-> Explorer Agent Profile
-> Badge Verification
-> Public Trust Report

## Commands

### `defaultsettle activate`

Purpose: Register and natively activate an autonomous agent.

Example:

```bash
defaultsettle activate agent:example-001
defaultsettle activate agent:example-001 --display-name "Example Agent"
defaultsettle activate agent:example-001 --base-url https://defaultverifier.com
defaultsettle activate agent:example-001 --json
```

Human output includes:

- agent registration
- activation receipt generation
- continuity initialization
- evidence chain creation
- agent profile availability
- badge availability

The command prints Agent ID, activation stage and type, SAR and Continuity
receipt IDs when returned, chain ID when returned, and Explorer/profile and
badge URLs when returned.

### `defaultsettle verify`

Purpose: Verify SAR receipts.

Example:

```bash
defaultsettle verify examples/receipt.json
defaultsettle verify examples/receipt.json --json
```

### `defaultsettle chain`

Purpose: Inspect linked SAR + Continuity evidence.

Example:

```bash
defaultsettle chain sha256:8b1aafe5dc4f1273220f1d6e634e7787e1c75df55e95dbe1cc6cd689182af688
defaultsettle chain <chain_id> --json
```

### `defaultsettle profile`

Purpose: Retrieve Agent Profile / Public Trust Report.

Example:

```bash
defaultsettle profile agent:start-loop-test-008
defaultsettle profile agent:start-loop-test-008 --json
```

## Development

Run the CLI module directly:

```bash
python -m defaultsettle.cli activate agent:example-001
```
