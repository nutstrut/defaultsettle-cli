# Defaultsettle CLI Security Policy

## Supported scope / current status

This CLI is under active development. `defaultsettle verify` has been tested
against the CLI's own example receipt and against the five shared SAR v0.1
fixtures used by the MCP and SettlementWitness verifiers (see
`reports/external-actions/defaultsettle-cli-verifier-parity-fix-20260708.md`
in the evidence repo). It is not yet claimed as production-hardened or
generally adopted.

## Local-first verification model

`defaultsettle verify` runs entirely offline against a local receipt file.
See [EGRESS.md](EGRESS.md) for the full network-behavior breakdown, including
which other commands (`speedrun`, `activate`, `profile`, `chain`) are online
by design.

## What verification proves

A `PASS`/`PASS` result (`Integrity` + `Signature Authentication`) means:

- the receipt's `receipt_id` matches the recomputed digest of its signed
  core fields (`task_id_hash`, `verdict`, `confidence`, `reason_code`, `ts`,
  `verifier_kid`, plus `counterparty` when present), so the receipt has not
  been tampered with since it was issued;
- for signed receipts, the Ed25519 signature verifies against the trusted
  public key resolved by `verifier_kid` in the bundled `TRUSTED_VERIFIER_KEYS`
  registry, so the receipt was issued by the verifier it claims to be from.

SAR-402 recorded receipts carry no verifier signature; `Signature
Authentication` reads `not_applicable` for those, not `PASS`.

## What verification does not prove

A verified receipt does not prove or certify:

- payment finality or that funds moved, were released, or were escrowed
- legal finality of any kind
- service quality, task correctness beyond the signed verdict, or fitness
  for any purpose
- production adoption, partnership, or third-party endorsement
- a structured resolver API (none exists in this CLI)
- ollama or any other local-model-stack compatibility (untested)
- Coinbase/CDP approval, or that any "Beachhead" phase has started

The CLI reports exactly what the signed receipt encodes. What you do with
that evidence is your responsibility.

## Safe handling of receipt files

Receipts can contain task metadata that may be sensitive (see EGRESS.md).
Do not commit real receipt files to public repositories or paste them into
shared channels unless you're sure they contain nothing sensitive. The
bundled `examples/` and `tests/fixtures/` receipts are safe, non-sensitive
sample/demo data.

## Public-key / verifier-key handling

`TRUSTED_VERIFIER_KEYS` in `defaultsettle/cli.py` pins the public keys for
`sar-prod-ed25519-01`, `-02`, and `-03`. Verification requires a receipt's
`verifier_kid` to be present in this local registry; a receipt signed by an
unlisted `kid` fails verification even if the signature is otherwise valid.
Key material embedded in a receipt itself is never trusted — only the
bundled registry is. Treat any change to this registry as a security-relevant
code change requiring review, not a routine update.

## Dependency / update expectations

This is a small CLI with a limited dependency surface. Keep dependencies
current and re-run `python3 -m unittest discover -s tests` after any
dependency or canonicalization-related change, since a canonicalization
mismatch silently breaks cross-verifier parity (see the verifier-parity fix
report referenced above for a concrete example of this class of bug).

## Unsupported claims

This project does not claim, and no documentation should imply:

- payment finality
- legal finality
- service-quality certification
- production adoption
- a structured resolver API
- ollama or local-stack compatibility
- Coinbase/CDP approval, or that a "Beachhead" phase has started

## Reporting a vulnerability

If you find a security issue in this CLI, please open a private report via
GitHub's security advisory feature on
https://github.com/nutstrut/defaultsettle-cli, or open an issue if the finding
is not sensitive. Do not include real, sensitive receipt contents in a public
report.
