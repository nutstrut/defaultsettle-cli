"""Command-line scaffold for Default Settlement."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


API_BASE_URL = "https://defaultverifier.com/v1"
REQUEST_TIMEOUT_SECONDS = 20


def coming_soon(_args: argparse.Namespace) -> None:
    """Placeholder command handler."""
    print("coming soon")


def fetch_json(url: str) -> dict[str, Any]:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "defaultsettle-cli/0.1",
        },
    )
    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            data = response.read()
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").strip()
        message = f"HTTP error {exc.code} while fetching {url}"
        if detail:
            message = f"{message}: {detail}"
        raise RuntimeError(message) from exc
    except URLError as exc:
        raise RuntimeError(f"Network error while fetching {url}: {exc.reason}") from exc
    except OSError as exc:
        raise RuntimeError(f"Network error while fetching {url}: {exc}") from exc

    try:
        decoded = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Invalid JSON response from {url}") from exc

    if not isinstance(decoded, dict):
        raise RuntimeError(f"Unexpected JSON response from {url}")
    return decoded


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


def handle_profile(args: argparse.Namespace) -> None:
    agent_id = args.agent_id
    encoded_agent_id = quote(agent_id, safe="")
    data = fetch_json(f"{API_BASE_URL}/agents/{encoded_agent_id}/summary")

    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return

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
            ("Badge URL", find_value(data, ("badge_url", "badgeUrl"))),
            (
                "Explorer URL",
                find_value(
                    data,
                    ("explorer_url", "explorerUrl", "trustscore_url", "trustscoreUrl", "profile_url", "profileUrl"),
                ),
            ),
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

    for command in ("activate", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.set_defaults(func=coming_soon)

    profile_parser = subparsers.add_parser("profile")
    profile_parser.add_argument("agent_id")
    profile_parser.add_argument("--json", action="store_true", help="Print the full JSON response.")
    profile_parser.set_defaults(func=handle_profile)

    chain_parser = subparsers.add_parser("chain")
    chain_parser.add_argument("chain_id")
    chain_parser.add_argument("--json", action="store_true", help="Print the full JSON response.")
    chain_parser.set_defaults(func=handle_chain)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
