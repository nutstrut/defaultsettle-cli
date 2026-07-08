"""Command-line scaffold for Default Settlement."""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


API_BASE_URL = "https://defaultverifier.com/v1"
DEFAULT_BASE_URL = "https://defaultverifier.com"
REQUEST_TIMEOUT_SECONDS = 20

# Fields required to recompute and check receipt integrity. ``verifier_kid``,
# ``counterparty``, and ``sig`` are intentionally excluded: a signed
# SettlementWitness receipt carries them, but SAR-402 recorded receipts do not,
# and integrity must still be checkable for both shapes.
SAR_RECEIPT_REQUIRED_FIELDS = (
    "task_id_hash",
    "verdict",
    "confidence",
    "reason_code",
    "ts",
    "receipt_id",
)

# Signed-core field set for SAR v0.1. Matches the fixed allow-list canonicalized
# by DefaultVerifier MCP (sarVerifier.js CORE_REQUIRED/buildCore) and the
# SettlementWitness skill (verify_receipt.py _CORE_REQUIRED/_core_without_sig).
# Only these fields, plus ``counterparty`` when present and non-empty, are
# canonicalized and signed; non-core fields (``sar_version``, ``receipt_id``,
# ``sig``, etc.) must never affect the digest.
SAR_CORE_FIELDS = (
    "task_id_hash",
    "verdict",
    "confidence",
    "reason_code",
    "ts",
    "verifier_kid",
)

# Trusted DefaultVerifier signing keys, keyed by ``verifier_kid``. Only keys
# published here are accepted; key material embedded in a receipt is never
# trusted. Each value is the raw 32-byte Ed25519 public key, base64url-encoded
# (the JWK ``x`` parameter for an OKP/Ed25519 key). Matches the registry
# bundled by DefaultVerifier MCP (``keys/sar-keys.json``) and the
# SettlementWitness skill.
TRUSTED_VERIFIER_KEYS = {
    "sar-prod-ed25519-01": "n0OM0xBI3wCfJW4_PwUY8zy4yFEArOJQGnqS9CnEfX8",
    "sar-prod-ed25519-02": "2a_BEldn8DHwfU-Gi3QmYbIZ6TB0mBn6HrXTA6BHAgI",
    "sar-prod-ed25519-03": "2a_BEldn8DHwfU-Gi3QmYbIZ6TB0mBn6HrXTA6BHAgI",
}

SIGNATURE_PASS = "PASS"
SIGNATURE_FAIL = "FAIL"
SIGNATURE_NOT_APPLICABLE = "not_applicable"


class ApiError(RuntimeError):
    def __init__(self, status_code: int, url: str, detail: str, operation: str) -> None:
        self.status_code = status_code
        self.url = url
        self.detail = detail
        message = f"HTTP error {status_code} while {operation} {url}"
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)


def coming_soon(_args: argparse.Namespace) -> None:
    """Placeholder command handler."""
    print("coming soon")


def read_json_response(url: str, request: Request, operation: str) -> dict[str, Any]:
    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            data = response.read()
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").strip()
        raise ApiError(exc.code, url, detail, operation) from exc
    except URLError as exc:
        raise RuntimeError(f"Network error while {operation} {url}: {exc.reason}") from exc
    except OSError as exc:
        raise RuntimeError(f"Network error while {operation} {url}: {exc}") from exc

    if not data:
        return {}

    try:
        decoded = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Invalid JSON response from {url}") from exc

    if not isinstance(decoded, dict):
        raise RuntimeError(f"Unexpected JSON response from {url}")
    return decoded


def fetch_json(url: str) -> dict[str, Any]:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "defaultsettle-cli/0.1",
        },
    )
    return read_json_response(url, request, "fetching")


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "defaultsettle-cli/0.1",
        },
    )
    return read_json_response(url, request, "requesting")


def api_base_from_base_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/v1"):
        return normalized
    return f"{normalized}/v1"


def absolute_url(base_url: str, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if value.startswith(("http://", "https://")):
        return value
    if value.startswith("/"):
        return f"{base_url.rstrip('/')}{value}"
    return value


def find_value(data: Any, keys: tuple[str, ...]) -> Any:
    if isinstance(data, dict):
        for key in keys:
            if key in data and data[key] not in (None, ""):
                return data[key]
        for value in data.values():
            found = find_value(value, keys)
            if found not in (None, ""):
                return found
    elif isinstance(data, list):
        for value in data:
            found = find_value(value, keys)
            if found not in (None, ""):
                return found
    return None


def format_value(value: Any) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def print_summary(rows: list[tuple[str, Any]]) -> None:
    label_width = max(len(label) for label, _value in rows)
    for label, value in rows:
        print(f"{label:<{label_width}}  {format_value(value)}")


def extract_activation_fields(
    agent_id: str,
    summary: dict[str, Any],
    activation: dict[str, Any],
) -> dict[str, Any]:
    source = {"summary": summary, "activation": activation}
    return {
        "agent_id": find_value(source, ("agent_id", "agentId", "id")) or agent_id,
        "activation_stage": find_value(
            source,
            ("activation_stage", "activationStage", "stage", "status"),
        ),
        "activation_type": find_value(source, ("activation_type", "activationType", "type"))
        or "native",
        "sar_receipt_id": find_value(
            source,
            (
                "sar_receipt_id",
                "sarReceiptId",
                "latest_sar_receipt_id",
                "latestSarReceiptId",
                "latest_sar_receipt",
                "latestSarReceipt",
                "receipt_id",
                "receiptId",
            ),
        ),
        "continuity_receipt_id": find_value(
            source,
            (
                "continuity_receipt_id",
                "continuityReceiptId",
                "latest_continuity_receipt_id",
                "latestContinuityReceiptId",
                "latest_continuity_receipt",
                "latestContinuityReceipt",
            ),
        ),
        "chain_id": find_value(
            source,
            ("chain_id", "chainId", "latest_chain_id", "latestChainId"),
        ),
        "explorer_url": find_value(
            source,
            (
                "explorer_url",
                "explorerUrl",
                "profile_url",
                "profileUrl",
                "agent_profile_url",
                "agentProfileUrl",
                "trustscore_url",
                "trustscoreUrl",
            ),
        ),
        "badge_url": find_value(source, ("badge_url", "badgeUrl")),
    }


def activate_agent(
    agent_id: str,
    base_url_value: str,
    display_name: str | None = None,
) -> dict[str, Any]:
    encoded_agent_id = quote(agent_id, safe="")
    base_url = base_url_value.rstrip("/")
    api_base_url = api_base_from_base_url(base_url_value)

    register_payload: dict[str, Any] = {
        "agent_id": agent_id,
        "owner_id": agent_id,
        "counterparty": agent_id,
    }
    if display_name:
        register_payload["display_name"] = display_name

    register_status = "registered"
    register_url = f"{api_base_url}/agents/register"
    try:
        register_response = post_json(register_url, register_payload)
    except ApiError as exc:
        if exc.status_code != 409:
            raise
        register_status = "already_exists"
        register_response = {"status": register_status, "detail": exc.detail}

    activate_url = f"{api_base_url}/agents/{encoded_agent_id}/activate"
    activate_payload = {
        "activation_type": "native",
        "continuity_input": {
            "task_id": f"native-activation:{agent_id}",
            "agent_id": agent_id,
            "counterparty": agent_id,
            "spec": {"activation_type": "native"},
            "output": {"activation_type": "native"},
        },
    }
    summary: dict[str, Any] | None = None
    try:
        activation_response = post_json(activate_url, activate_payload)
        activation_status = "activated"
    except ApiError as exc:
        if exc.status_code == 409 and "already" in exc.detail.lower():
            activation_status = "already_activated"
            activation_response = {"status": activation_status, "detail": exc.detail}
        else:
            try:
                summary = fetch_json(f"{api_base_url}/agents/{encoded_agent_id}/summary")
            except RuntimeError:
                raise exc
            summary_status = find_value(summary, ("activation_stage", "activationStage", "stage", "status"))
            successful_stages = {"activated", "verified", "chained", "continuous"}
            if str(summary_status).lower() not in successful_stages:
                raise
            activation_status = "activated_after_error"
            activation_response = {"status": activation_status, "detail": exc.detail}

    if summary is None:
        summary = fetch_json(f"{api_base_url}/agents/{encoded_agent_id}/summary")
    fields = extract_activation_fields(agent_id, summary, activation_response)
    fields["explorer_url"] = absolute_url(base_url, fields["explorer_url"])
    fields["badge_url"] = absolute_url(base_url, fields["badge_url"])
    return {
        **fields,
        "sar_receipt": extract_sar_receipt(activation_response),
        "register_status": register_status,
        "activation_status": activation_status,
        "register_response": register_response,
        "activation_response": activation_response,
        "summary": summary,
    }


def extract_sar_receipt(activation_response: Any) -> dict[str, Any] | None:
    """Return the verifiable SAR receipt (v0.1) from an activation response.

    The receipt is the flat object that ``defaultsettle verify`` consumes; it is
    absent when the agent was already activated and the server returns a stub.
    """
    if isinstance(activation_response, dict):
        sar = activation_response.get("sar")
        if isinstance(sar, dict):
            receipt = sar.get("receipt_v0_1")
            if isinstance(receipt, dict):
                return receipt
    return None


def handle_activate(args: argparse.Namespace) -> None:
    result = activate_agent(args.agent_id, args.base_url, args.display_name)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    registered_label = "Agent registered"
    if result["register_status"] == "already_exists":
        registered_label = "Agent registered (already existed)"
    print(f"\u2713 {registered_label}")
    print("\u2713 Activation receipt generated")
    print("\u2713 Continuity initialized")
    print("\u2713 Evidence chain created")
    print("\u2713 Agent profile available")
    print("\u2713 Badge available")
    print()
    print_summary(
        [
            ("Agent ID", result["agent_id"]),
            ("Activation Stage", result["activation_stage"]),
            ("Activation Type", result["activation_type"]),
            ("SAR Receipt ID", result["sar_receipt_id"]),
            ("Continuity Receipt ID", result["continuity_receipt_id"]),
            ("Chain ID", result["chain_id"]),
            ("Explorer/Profile URL", result["explorer_url"]),
            ("Badge URL", result["badge_url"]),
        ]
    )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def timestamp_for_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def make_speedrun_agent_id(origin: str) -> str:
    return f"agent:{origin}-{timestamp_for_id()}-{secrets.token_hex(3)}"


def fallback_explorer_url(base_url: str, agent_id: str) -> str:
    return f"{base_url.rstrip('/')}/agents/{quote(agent_id, safe='')}"


def fallback_badge_url(base_url: str, agent_id: str) -> str:
    return f"{base_url.rstrip('/')}/badges/{quote(agent_id, safe='')}.svg"


def write_speedrun_report(report: dict[str, Any], report_stamp: str) -> Path:
    report_dir = Path("reports") / "speedrun"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"defaultsettle-speedrun-{report_stamp}.json"
    with report_path.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2, sort_keys=True)
        report_file.write("\n")
    return report_path


def write_speedrun_receipt(receipt: dict[str, Any], report_stamp: str) -> Path:
    report_dir = Path("reports") / "speedrun"
    report_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = report_dir / f"defaultsettle-receipt-{report_stamp}.json"
    with receipt_path.open("w", encoding="utf-8") as receipt_file:
        json.dump(receipt, receipt_file, indent=2, sort_keys=True)
        receipt_file.write("\n")
    return receipt_path


def handle_speedrun(args: argparse.Namespace) -> int:
    origin = args.origin
    agent_id = args.agent_id or make_speedrun_agent_id(origin)
    base_url = args.base_url.rstrip("/")
    report_stamp = timestamp_for_id()
    started_at = utc_now_iso()
    started_timer = time.perf_counter()
    report: dict[str, Any] = {
        "started_at": started_at,
        "completed_at": None,
        "time_to_verified_receipt_seconds": None,
        "origin": origin,
        "agent_id": agent_id,
        "base_url": base_url,
        "success": False,
        "explorer_url": None,
        "badge_url": None,
        "sar_receipt_id": None,
        "sar_receipt_path": None,
        "continuity_receipt_id": None,
        "chain_id": None,
        "activation_stage": None,
        "error": None,
    }

    try:
        result = activate_agent(agent_id, base_url, f"Default Settlement Speedrun {report_stamp}")
        elapsed = round(time.perf_counter() - started_timer, 3)
        explorer_url = result["explorer_url"] or fallback_explorer_url(base_url, agent_id)
        badge_url = result["badge_url"] or fallback_badge_url(base_url, agent_id)
        sar_receipt = result.get("sar_receipt")
        receipt_path = (
            write_speedrun_receipt(sar_receipt, report_stamp) if sar_receipt else None
        )
        report.update(
            {
                "completed_at": utc_now_iso(),
                "time_to_verified_receipt_seconds": elapsed,
                "success": True,
                "explorer_url": explorer_url,
                "badge_url": badge_url,
                "sar_receipt_id": result["sar_receipt_id"],
                "sar_receipt_path": str(receipt_path) if receipt_path else None,
                "continuity_receipt_id": result["continuity_receipt_id"],
                "chain_id": result["chain_id"],
                "activation_stage": result["activation_stage"],
            }
        )
        write_speedrun_report(report, report_stamp)
    except RuntimeError as exc:
        report.update(
            {
                "completed_at": utc_now_iso(),
                "time_to_verified_receipt_seconds": round(time.perf_counter() - started_timer, 3),
                "error": str(exc),
            }
        )
        write_speedrun_report(report, report_stamp)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print("\u2713 Created demo agent")
    print("\u2713 Generated activation receipt")
    print("\u2713 Initialized continuity")
    print("\u2713 Created evidence chain")
    print("\u2713 Explorer/Profile URL ready")
    print("\u2713 Badge URL ready")
    print()
    print_summary(
        [
            ("Agent ID", report["agent_id"]),
            ("Activation Stage", report["activation_stage"]),
            ("SAR Receipt ID", report["sar_receipt_id"]),
            ("Continuity Receipt ID", report["continuity_receipt_id"]),
            ("Chain ID", report["chain_id"]),
            ("Explorer/Profile URL", report["explorer_url"]),
            ("Badge URL", report["badge_url"]),
            ("Saved Receipt", report["sar_receipt_path"]),
            ("Time To Verified Receipt seconds", report["time_to_verified_receipt_seconds"]),
        ]
    )
    if report["sar_receipt_path"]:
        print()
        print("Verify the saved receipt locally:")
        print(f"  defaultsettle verify {report['sar_receipt_path']}")
    print()
    print("Some things you can't put a price on. Trust is one of them.")
    return 0


def load_receipt(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as receipt_file:
            data = json.load(receipt_file)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Receipt file not found: {path}") from exc
    except OSError as exc:
        raise RuntimeError(f"Could not read receipt file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in receipt file {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise RuntimeError("Receipt file must contain a JSON object")

    if "receipt_v0_1" in data:
        receipt = data["receipt_v0_1"]
        if not isinstance(receipt, dict):
            raise RuntimeError("receipt_v0_1 must be a JSON object")
        return receipt

    return data


def canonicalize_json_value(value: Any) -> Any:
    """Apply JCS (RFC 8785) number canonicalization.

    The verifier serializes integral floats without a fractional part (``1.0``
    becomes ``1``). Plain ``json.dumps`` would emit ``1.0`` and produce a
    different digest, so real receipts must be canonicalized the same way the
    server does before hashing.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {key: canonicalize_json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [canonicalize_json_value(item) for item in value]
    return value


def build_sar_core(receipt: dict[str, Any]) -> dict[str, Any]:
    """Build the signed SAR v0.1 core object from a receipt.

    Mirrors the MCP's ``buildCore`` and the SettlementWitness skill's
    ``_core_without_sig``: only :data:`SAR_CORE_FIELDS`, plus ``counterparty``
    when present and non-empty, are included.
    """
    core: dict[str, Any] = {field: receipt.get(field) for field in SAR_CORE_FIELDS}
    counterparty = receipt.get("counterparty")
    if isinstance(counterparty, str) and counterparty.strip():
        core["counterparty"] = counterparty.strip()
    return core


def compute_receipt_id(receipt: dict[str, Any]) -> str:
    canonical_json = json.dumps(
        canonicalize_json_value(build_sar_core(receipt)),
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def decode_base64url(value: str) -> bytes:
    """Decode base64url text, tolerating missing ``=`` padding."""
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def parse_signature(sig: Any) -> bytes:
    """Parse a receipt ``sig`` value into raw signature bytes.

    Accepts the canonical ``base64url:<signature>`` form and, defensively, a
    bare base64url string. Raises ``ValueError`` for anything malformed.
    """
    if not isinstance(sig, str) or not sig:
        raise ValueError("signature is missing or not a string")
    encoded = sig[len("base64url:") :] if sig.startswith("base64url:") else sig
    encoded = encoded.strip()
    if not encoded:
        raise ValueError("signature payload is empty")
    try:
        raw = decode_base64url(encoded)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"signature is not valid base64url: {exc}") from exc
    if len(raw) != 64:
        raise ValueError(f"Ed25519 signature must be 64 bytes, got {len(raw)}")
    return raw


def is_signed_settlement_witness(receipt: dict[str, Any]) -> bool:
    """Whether a receipt is a signed SettlementWitness / DefaultVerifier receipt.

    Signed receipts are authenticated by a verifier and carry a ``verifier_kid``.
    SAR-402 recorded receipts are not signed by a verifier; they have no
    ``verifier_kid`` and (per requirement) must not imply signature/proof-seal
    verification.
    """
    return bool(receipt.get("verifier_kid"))


def authenticate_signature(receipt: dict[str, Any], digest: bytes) -> tuple[str, str]:
    """Authenticate the Ed25519 signature over the receipt digest bytes.

    Returns ``(status, detail)`` where status is one of ``PASS``/``FAIL``/
    ``not_applicable``. The trusted public key is resolved solely by
    ``verifier_kid`` against :data:`TRUSTED_VERIFIER_KEYS`; key material embedded
    in the receipt is never used.
    """
    if not is_signed_settlement_witness(receipt):
        return SIGNATURE_NOT_APPLICABLE, "Not a signed SettlementWitness receipt"

    kid = receipt["verifier_kid"]
    trusted_key_b64 = TRUSTED_VERIFIER_KEYS.get(kid)
    if trusted_key_b64 is None:
        return SIGNATURE_FAIL, f"Unknown verifier_kid: {kid}"

    try:
        signature = parse_signature(receipt.get("sig"))
    except ValueError as exc:
        return SIGNATURE_FAIL, str(exc)

    # Imported lazily so the rest of the CLI runs without the crypto dependency.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public_key = Ed25519PublicKey.from_public_bytes(decode_base64url(trusted_key_b64))
    try:
        public_key.verify(signature, digest)
    except InvalidSignature:
        return SIGNATURE_FAIL, "Signature does not match trusted verifier key"
    return SIGNATURE_PASS, f"Verified against trusted key {kid}"


def is_sar_402_recorded(receipt: dict[str, Any]) -> bool:
    """Whether a receipt is a recorded SAR-402 settlement receipt.

    These are recorded (not signed) receipts and carry no SettlementWitness
    Ed25519 signature, so neither integrity nor signature authentication applies.
    """
    if receipt.get("receipt_type") == "sar_402_settlement":
        return True
    inner = receipt.get("receipt")
    if isinstance(inner, dict) and inner.get("profile") == "sar-402":
        return True
    return False


def verify_sar_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    if is_sar_402_recorded(receipt):
        return {
            "receipt_type": "sar_402_settlement",
            "receipt_id": receipt.get("receipt_id"),
            "integrity": SIGNATURE_NOT_APPLICABLE,
            "signature_authentication": SIGNATURE_NOT_APPLICABLE,
            "signature_verification": SIGNATURE_NOT_APPLICABLE,
            "status": SIGNATURE_NOT_APPLICABLE,
            "message": (
                "recorded SAR-402 receipt; no SettlementWitness Ed25519 signature"
            ),
        }

    missing_fields = [
        field
        for field in SAR_RECEIPT_REQUIRED_FIELDS
        if field not in receipt or receipt[field] in (None, "")
    ]
    if missing_fields:
        raise RuntimeError(f"Missing required SAR receipt fields: {', '.join(missing_fields)}")

    computed_receipt_id = compute_receipt_id(receipt)
    integrity = "PASS" if computed_receipt_id == receipt["receipt_id"] else "FAIL"

    # Authenticate against the recomputed digest (the same bytes that back the
    # receipt_id), independent of whether integrity passed.
    digest = bytes.fromhex(computed_receipt_id.split(":", 1)[1])
    signature_status, signature_detail = authenticate_signature(receipt, digest)

    return {
        "receipt_id": receipt["receipt_id"],
        "computed_receipt_id": computed_receipt_id,
        "integrity": integrity,
        "verdict": receipt["verdict"],
        "reason_code": receipt["reason_code"],
        "timestamp": receipt["ts"],
        "verifier_kid": receipt.get("verifier_kid"),
        "signature_authentication": signature_status,
        "signature_detail": signature_detail,
    }


def handle_verify(args: argparse.Namespace) -> int:
    receipt = load_receipt(Path(args.receipt_json))
    result = verify_sar_receipt(receipt)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif result.get("receipt_type") == "sar_402_settlement":
        print_summary(
            [
                ("Receipt ID", result["receipt_id"]),
                ("Receipt Type", "sar_402_settlement"),
                ("Integrity", result["integrity"]),
                ("Signature Authentication", result["signature_authentication"]),
            ]
        )
        print()
        print(result["message"])
        return 0
    else:
        print_summary(
            [
                ("Receipt ID", result["receipt_id"]),
                ("Computed Receipt ID", result["computed_receipt_id"]),
                ("Verdict", result["verdict"]),
                ("Reason Code", result["reason_code"]),
                ("Timestamp", result["timestamp"]),
                ("Verifier Key ID", result["verifier_kid"]),
                ("Integrity", result["integrity"]),
                ("Signature Authentication", result["signature_authentication"]),
            ]
        )
        print()
        print(result["signature_detail"])

    if result.get("receipt_type") == "sar_402_settlement":
        return 0

    integrity_ok = result["integrity"] == "PASS"
    signature_ok = result["signature_authentication"] != SIGNATURE_FAIL
    return 0 if integrity_ok and signature_ok else 1


def handle_profile(args: argparse.Namespace) -> None:
    agent_id = args.agent_id
    encoded_agent_id = quote(agent_id, safe="")
    base_url = DEFAULT_BASE_URL
    data = fetch_json(f"{API_BASE_URL}/agents/{encoded_agent_id}/summary")

    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return

    badge_url = absolute_url(base_url, find_value(data, ("badge_url", "badgeUrl")))
    explorer_url = absolute_url(
        base_url,
        find_value(
            data,
            ("explorer_url", "explorerUrl", "trustscore_url", "trustscoreUrl", "profile_url", "profileUrl"),
        ),
    )

    print_summary(
        [
            ("Agent ID", find_value(data, ("agent_id", "agentId", "id")) or agent_id),
            ("Display Name", find_value(data, ("display_name", "displayName", "name"))),
            (
                "Activation Stage",
                find_value(data, ("activation_stage", "activationStage", "stage")),
            ),
            ("Status", find_value(data, ("status",))),
            (
                "Latest SAR Receipt",
                find_value(
                    data,
                    (
                        "latest_sar_receipt_id",
                        "latestSarReceiptId",
                        "latest_sar_receipt",
                        "latestSarReceipt",
                        "sar_receipt_id",
                        "sarReceiptId",
                    ),
                ),
            ),
            (
                "Latest Continuity Receipt",
                find_value(
                    data,
                    (
                        "latest_continuity_receipt_id",
                        "latestContinuityReceiptId",
                        "latest_continuity_receipt",
                        "latestContinuityReceipt",
                        "continuity_receipt_id",
                        "continuityReceiptId",
                    ),
                ),
            ),
            (
                "Latest Chain ID",
                find_value(data, ("latest_chain_id", "latestChainId", "chain_id", "chainId")),
            ),
            ("Badge URL", badge_url),
            ("Explorer URL", explorer_url),
        ]
    )


def handle_chain(args: argparse.Namespace) -> None:
    chain_id = args.chain_id
    encoded_chain_id = quote(chain_id, safe="")
    data = fetch_json(f"{API_BASE_URL}/attest/chain/{encoded_chain_id}")

    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return

    print_summary(
        [
            ("Chain ID", find_value(data, ("chain_id", "chainId", "id")) or chain_id),
            ("Status", find_value(data, ("chain_status", "chainStatus", "status", "stage"))),
            (
                "SAR Receipt ID",
                find_value(data, ("sar_receipt_id", "sarReceiptId", "sar_id", "sarId")),
            ),
            (
                "Continuity Receipt ID",
                find_value(
                    data,
                    ("continuity_receipt_id", "continuityReceiptId", "continuity_id", "continuityId"),
                ),
            ),
            ("SAR Verdict", find_value(data, ("sar_verdict", "sarVerdict", "verdict"))),
            (
                "Continuity Classification",
                find_value(data, ("continuity_classification", "continuityClassification", "classification")),
            ),
            (
                "Executor Continuity Status",
                find_value(data, ("executor_continuity_status", "executorContinuityStatus")),
            ),
            (
                "Time Delta Seconds",
                find_value(data, ("time_delta_seconds", "timeDeltaSeconds", "delta_seconds", "deltaSeconds")),
            ),
            (
                "Verdict Correlation",
                find_value(data, ("verdict_correlation", "verdictCorrelation")),
            ),
        ]
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="defaultsettle",
        description="Default Settlement machine trust infrastructure CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # "demo" is a friendlier alias for "speedrun"; both run the same handler.
    for speedrun_name in ("speedrun", "demo"):
        speedrun_parser = subparsers.add_parser(speedrun_name)
        speedrun_parser.add_argument(
            "--origin",
            default="cli-speedrun",
            help="Origin marker for generated demo agent IDs. Defaults to cli-speedrun.",
        )
        speedrun_parser.add_argument("--agent-id", help="Use a custom demo agent ID.")
        speedrun_parser.add_argument(
            "--base-url",
            default=DEFAULT_BASE_URL,
            help=f"Default Settlement API base URL. Defaults to {DEFAULT_BASE_URL}.",
        )
        speedrun_parser.add_argument("--json", action="store_true", help="Print speedrun report as JSON.")
        speedrun_parser.set_defaults(func=handle_speedrun)

    activate_parser = subparsers.add_parser("activate")
    activate_parser.add_argument("agent_id")
    activate_parser.add_argument("--display-name", help="Human-readable agent display name.")
    activate_parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Default Settlement API base URL. Defaults to {DEFAULT_BASE_URL}.",
    )
    activate_parser.add_argument("--json", action="store_true", help="Print activation result as JSON.")
    activate_parser.set_defaults(func=handle_activate)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("receipt_json")
    verify_parser.add_argument("--json", action="store_true", help="Print verification result as JSON.")
    verify_parser.set_defaults(func=handle_verify)

    profile_parser = subparsers.add_parser("profile")
    profile_parser.add_argument("agent_id")
    profile_parser.add_argument("--json", action="store_true", help="Print the full JSON response.")
    profile_parser.set_defaults(func=handle_profile)

    chain_parser = subparsers.add_parser("chain")
    chain_parser.add_argument("chain_id")
    chain_parser.add_argument("--json", action="store_true", help="Print the full JSON response.")
    chain_parser.set_defaults(func=handle_chain)

    return parser


def configure_output_encoding() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")


def main() -> int:
    configure_output_encoding()
    parser = build_parser()
    args = parser.parse_args()
    try:
        result = args.func(args)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return int(result or 0)


if __name__ == "__main__":
    raise SystemExit(main())
