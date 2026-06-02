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

### `defaultsettle profile`

Purpose: Retrieve Agent Profile / Public Trust Report.

## Development

Run the CLI module directly:

```bash
python -m defaultsettle.cli activate
```

Each scaffolded command currently prints:

```text
coming soon
```
