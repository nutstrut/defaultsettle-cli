# Default Settlement CLI

Default Settlement is machine trust infrastructure for autonomous systems.

## Speedrun: zero to first proof

Default Settlement Speedrun is the fastest path from a fresh checkout to a
verified demo activation proof. It requires no account, API key, OAuth flow, or
environment variables.

```bash
python -m defaultsettle.cli speedrun
```

Target: under 60 seconds.

The command creates a unique demo agent ID, registers and activates it through
the public activation endpoints, fetches the profile summary, prints receipt and
Explorer links, and writes a local report to `reports/speedrun/`.

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

### `defaultsettle speedrun`

Purpose: Create demo activation proof as quickly as possible.

Example:

```bash
defaultsettle speedrun
defaultsettle speedrun --json
defaultsettle speedrun --origin cli-speedrun --base-url https://defaultverifier.com
```

Safety: this command only creates demo activation proof. It does not post, does
not use OAuth, and does not mutate anything except registering and activating
the demo agent through public activation endpoints.

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
