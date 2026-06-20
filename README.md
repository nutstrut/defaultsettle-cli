# Default Settlement CLI

**Run one command. Get a signed receipt proving an AI agent completed a task. Verify it locally.**

No account. No API key. No OAuth. No environment variables. One command, one live signed receipt, in a few seconds.

## Quickstart

```bash
python3 -m pip install -e .
defaultsettle speedrun
```

That's it. `speedrun` (alias: `defaultsettle demo`) creates a fresh demo agent, runs it
through the public Default Settlement endpoints, and prints a verified result:

```text
✓ Created demo agent
✓ Generated activation receipt
✓ Initialized continuity
✓ Created evidence chain
✓ Explorer/Profile URL ready
✓ Badge URL ready

Agent ID                          agent:cli-speedrun-20260619-191518-29ee58
Activation Stage                  chained
SAR Receipt ID                    a54bcd18d8d5dabc94b307dcfcc87c4297e24b845cd2ea730459bd0c5a06ccdf
Continuity Receipt ID             sha256:146c4d6b...27b4f6
Chain ID                          sha256:3f53ee66...96fdc47
Explorer/Profile URL              https://defaultverifier.com/trustscore/agent:cli-speedrun-...
Badge URL                         https://defaultverifier.com/badge/agent:cli-speedrun-....svg
Saved Receipt                     reports/speedrun/defaultsettle-receipt-20260619-191518.json
Time To Verified Receipt seconds  3.376

Verify the saved receipt locally:
  defaultsettle verify reports/speedrun/defaultsettle-receipt-20260619-191518.json
```

(IDs, URLs and timing are unique per run — yours will differ.)

### What just happened

In one command you produced a **signed, verifiable receipt** that a machine agent
completed a task. The run:

- created a unique demo agent and activated it,
- got back a signed receipt (the `SAR Receipt`) plus a continuity receipt and an
  evidence chain linking them,
- gave you a public **Explorer/Profile URL** and a **Badge URL** anyone can open,
- saved the receipt to `reports/speedrun/` so you can verify it yourself.

### Verify it yourself

The run prints the exact command. Verification reads the saved receipt and runs
**fully offline** — no network needed:

```bash
defaultsettle verify reports/speedrun/defaultsettle-receipt-<timestamp>.json
```

```text
Receipt ID                sha256:dcf8f27a...3361b42
Computed Receipt ID       sha256:dcf8f27a...3361b42
Verdict                   PASS
Reason Code               SPEC_MATCH
Integrity                 PASS
Signature Authentication  PASS
```

`verify` performs two independent checks:

1. **Integrity** — it recomputes the receipt's canonical hash and checks it
   against the `receipt_id` baked into the receipt. If a single field were
   altered, the hashes diverge and `Integrity` reads `FAIL`. This proves the
   receipt **has not been tampered with** since it was issued.
2. **Signature authentication** — for signed SettlementWitness / DefaultVerifier
   receipts, it verifies the issuer's **Ed25519 signature** over the same digest
   using the trusted public key resolved by `verifier_kid`. Key material embedded
   in the receipt is never trusted. An unknown `verifier_kid`, or a
   missing/malformed/invalid signature, reads `FAIL`. This proves the receipt was
   **issued by the verifier it claims**, not just left untampered.

`verify` exits non-zero if either integrity or signature authentication fails.

> SAR-402 recorded receipts are not signed SettlementWitness receipts: they carry
> no verifier signature, so `Signature Authentication` reads `not_applicable`
> while integrity is still checked. The tool never implies a signature or
> proof-seal was verified when one was not.

## Why receipts matter

When autonomous agents act on your behalf, "trust me, it worked" doesn't scale.
A receipt turns a claim into evidence: a portable, hash-addressed record of what
an agent did and how it was judged, that a counterparty can check without calling
you and without trusting your word. Default Settlement issues those receipts and
keeps a public trust profile per agent.

## Commands

### `defaultsettle speedrun` (alias `demo`)

Fastest path from a fresh checkout to a verified demo proof.

```bash
defaultsettle speedrun
defaultsettle demo --json
defaultsettle speedrun --base-url https://defaultverifier.com
```

Safe by design: it only creates a **demo** activation proof through public
endpoints. It does not post anything externally, does not move money or sign a
wallet transaction, does not use OAuth, and needs no local services. It writes a
report and the receipt to `reports/speedrun/`.

### `defaultsettle verify`

Verify a saved SAR receipt locally (offline): receipt integrity plus Ed25519
signature authentication for signed receipts.

```bash
defaultsettle verify reports/speedrun/defaultsettle-receipt-<timestamp>.json
defaultsettle verify examples/receipt.json --json
```

### `defaultsettle activate`

Register and natively activate a real agent of your own.

```bash
defaultsettle activate agent:example-001 --display-name "Example Agent"
defaultsettle activate agent:example-001 --json
```

### `defaultsettle profile`

Retrieve an agent's public trust profile.

```bash
defaultsettle profile agent:example-001
defaultsettle profile agent:example-001 --json
```

### `defaultsettle chain`

Inspect a linked evidence chain by its chain ID.

```bash
defaultsettle chain sha256:<chain_id>
defaultsettle chain sha256:<chain_id> --json
```

## Security & trust model

- **Speedrun is read-mostly and safe.** It registers and activates a throwaway
  demo agent through public endpoints. No account, key, OAuth, or env var is
  required, and nothing is posted to third parties.
- **Not a payment or wallet action.** Nothing in this CLI moves funds or signs a
  blockchain transaction.
- **Receipts are content-addressed.** A receipt's `receipt_id` is a SHA-256 over
  its canonical contents, so any change to the receipt body is detectable.
- **Offline integrity and authenticity.** `verify` recomputes that hash locally
  with no network call, and for signed receipts it authenticates the issuer's
  Ed25519 signature against a trusted, pinned verifier public key. SAR-402
  recorded receipts have no signature, so the tool reports
  `Signature Authentication: not_applicable` rather than implying more than it
  checks.
- **Default endpoint** is `https://defaultverifier.com`; override with
  `--base-url` for a different environment.

## Development

Run from source without installing:

```bash
python3 -m defaultsettle.cli --help
python3 -m defaultsettle.cli speedrun
```

Run the local test suite (no network required):

```bash
python3 -m unittest discover -s tests
```

## Links

- Verifier & public Explorer: https://defaultverifier.com
- An agent's trust profile: `https://defaultverifier.com/trustscore/<agent_id>`
- An agent's badge: `https://defaultverifier.com/badge/<agent_id>.svg`

---

### Repo metadata (for maintainers)

Suggested GitHub description:

> CLI for generating signed receipts for AI-agent actions in seconds.

Suggested topics:

```
ai-agents
verification
receipts
trust
cli
default-settlement
agent-infrastructure
provenance
```

Launch one-liner to share:

> Run one command, get a live signed receipt that an AI agent completed a task,
> and verify it locally — no account, no API key, no setup.
> `pip install -e . && defaultsettle speedrun`
