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

Purpose: Register or activate an autonomous agent.

Future output:

- `activation_id`
- `agent_profile_url`
- `badge_markdown`

### `defaultsettle verify`

Purpose: Verify SAR receipts.

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
python -m defaultsettle.cli activate
```

Placeholder commands currently print:

```text
coming soon
```
