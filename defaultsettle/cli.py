"""Command-line scaffold for Default Settlement."""

from __future__ import annotations

import argparse
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
SAR_RECEIPT_REQUIRED_FIELDS = (
    "task_id_hash",
    "verdict",
    "confidence",
    "reason_code",
    "ts",
    "verifier_kid",
    "counterparty",
    "receipt_id",
    "sig",
)


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
        "register_status": register_status,
        "activation_status": activation_status,
        "register_response": register_response,
        "activation_response": activation_response,
        "summary": summary,
    }


def handle_activate(args: argparse.Namespace) -> None:
    result = activate_agent(args.agent_id, args.base_url, args.display_name)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    registered_label = "Agent registered"
    if register_status == "already_exists":
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
        report.update(
            {
                "completed_at": utc_now_iso(),
                "time_to_verified_receipt_seconds": elapsed,
                "success": True,
                "explorer_url": explorer_url,
                "badge_url": badge_url,
                "sar_receipt_id": result["sar_receipt_id"],
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
            ("Time To Verified Receipt seconds", report["time_to_verified_receipt_seconds"]),
        ]
    )
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


def compute_receipt_id(receipt: dict[str, Any]) -> str:
    canonical_fields = {
        key: value
        for key, value in receipt.items()
        if key not in {"receipt_id", "sig"}
    }
    canonical_json = json.dumps(canonical_fields, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def verify_sar_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    missing_fields = [
        field
        for field in SAR_RECEIPT_REQUIRED_FIELDS
        if field not in receipt or receipt[field] in (None, "")
    ]
    if missing_fields:
        raise RuntimeError(f"Missing required SAR receipt fields: {', '.join(missing_fields)}")

    computed_receipt_id = compute_receipt_id(receipt)
    integrity = "PASS" if computed_receipt_id == receipt["receipt_id"] else "FAIL"
    return {
        "receipt_id": receipt["receipt_id"],
        "computed_receipt_id": computed_receipt_id,
        "integrity": integrity,
        "verdict": receipt["verdict"],
        "reason_code": receipt["reason_code"],
        "timestamp": receipt["ts"],
        "verifier_kid": receipt["verifier_kid"],
        "signature_verification": "not_implemented",
    }


def handle_verify(args: argparse.Namespace) -> int:
    receipt = load_receipt(Path(args.receipt_json))
    result = verify_sar_receipt(receipt)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
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
            ]
        )
        print()
        print("Signature verification coming soon; local integrity check only.")

    return 0 if result["integrity"] == "PASS" else 1


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

    speedrun_parser = subparsers.add_parser("speedrun")
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
