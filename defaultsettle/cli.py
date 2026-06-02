"""Command-line scaffold for Default Settlement."""

from __future__ import annotations

import argparse


COMMANDS = ("activate", "verify", "profile", "chain")


def coming_soon(_args: argparse.Namespace) -> None:
    """Placeholder command handler."""
    print("coming soon")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="defaultsettle",
        description="Default Settlement machine trust infrastructure CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command in COMMANDS:
        subparser = subparsers.add_parser(command)
        subparser.set_defaults(func=coming_soon)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
