# Defaultsettle CLI Egress Policy

`defaultsettle verify` is local-first.

Local receipt verification (`defaultsettle verify <receipt.json>`) uses local
files only:

- reads the receipt JSON from disk,
- recomputes the canonical digest of the signed core fields,
- checks it against the receipt's `receipt_id`,
- for signed receipts, authenticates the Ed25519 signature against the
  bundled, pinned `TRUSTED_VERIFIER_KEYS` registry (`sar-prod-ed25519-01`,
  `-02`, `-03`).

For this tested local verification path, **no account, API key, hosted
callback, or remote fetch is required.**

## Evidence

The verifier-parity fix (`reports/external-actions/defaultsettle-cli-verifier-parity-fix-20260708.md`
in the evidence repo) traced `defaultsettle verify` against a shared SAR v0.1
fixture with `strace -f -e trace=network,connect,socket` and recorded **zero**
socket/network syscalls. This is the same result previously recorded for the
CLI's own example receipt.

This is not a claim that every command, or every future command, never uses
the network — see below.

## Commands that do use the network

Several other CLI commands are online by design and contact
`https://defaultverifier.com` (or a `--base-url` override):

- `defaultsettle speedrun` / `demo` — creates a demo agent and receipt through
  public endpoints
- `defaultsettle activate` — registers/activates an agent
- `defaultsettle profile` — fetches a public trust profile
- `defaultsettle chain` — fetches a public evidence chain

Only `defaultsettle verify` on a local receipt file is covered by the
local-first, zero-egress claim above.

## Future fetch/resolve commands

If future commands are added that fetch or resolve receipts remotely, they
must be explicit, clearly documented, and must distinguish local
verification mode from remote-fetch mode. Local verification of a file you
already have on disk must not silently start making network calls.

## Receipt files may be sensitive

Receipts can contain task metadata (`task_id_hash`, `spec`, timestamps,
counterparty identifiers, etc.). Treat local receipt files as potentially
sensitive data. Do not send a private receipt to Default Settlement, or
anywhere else, unless a future command explicitly requests it and you
consent to that specific transmission.

## Public keys

The `TRUSTED_VERIFIER_KEYS` registry bundled in `defaultsettle/cli.py` is a
pinned trust root, not fetched at verify time. Key updates should be
reviewed and versioned like any other code change, not pulled automatically.

## Telemetry

The CLI has no telemetry. `defaultsettle verify` does not report usage,
results, or receipt contents anywhere.
