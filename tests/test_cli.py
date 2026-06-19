"""Local smoke tests for the defaultsettle CLI.

These tests never touch the network: they exercise argument parsing, receipt
canonicalization, and the console entry point only.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from defaultsettle import cli

EXAMPLE_RECEIPT = Path(__file__).resolve().parent.parent / "examples" / "receipt.json"


class ParserTests(unittest.TestCase):
    def test_known_subcommands_parse(self) -> None:
        parser = cli.build_parser()
        for command in ("speedrun", "demo", "activate", "verify", "profile", "chain"):
            with self.subTest(command=command):
                if command in ("activate", "profile", "chain", "verify"):
                    args = parser.parse_args([command, "x"])
                else:
                    args = parser.parse_args([command])
                self.assertTrue(callable(args.func))

    def test_demo_is_speedrun_alias(self) -> None:
        parser = cli.build_parser()
        self.assertIs(
            parser.parse_args(["demo"]).func,
            parser.parse_args(["speedrun"]).func,
        )


class CanonicalizationTests(unittest.TestCase):
    def test_integral_float_becomes_int(self) -> None:
        self.assertEqual(cli.canonicalize_json_value(1.0), 1)
        self.assertEqual(cli.canonicalize_json_value({"c": 0.0}), {"c": 0})

    def test_fractional_float_preserved(self) -> None:
        self.assertEqual(cli.canonicalize_json_value(0.95), 0.95)

    def test_bool_not_coerced(self) -> None:
        self.assertIs(cli.canonicalize_json_value(True), True)


class VerifyTests(unittest.TestCase):
    def test_example_receipt_integrity_passes(self) -> None:
        receipt = cli.load_receipt(EXAMPLE_RECEIPT)
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["computed_receipt_id"], receipt["receipt_id"])

    def test_load_receipt_unwraps_v0_1(self) -> None:
        flat = cli.load_receipt(EXAMPLE_RECEIPT)
        wrapped_path = EXAMPLE_RECEIPT.parent / "_wrapped_tmp.json"
        wrapped_path.write_text(json.dumps({"receipt_v0_1": flat}))
        try:
            self.assertEqual(cli.load_receipt(wrapped_path), flat)
        finally:
            wrapped_path.unlink()

    def test_tampered_receipt_fails(self) -> None:
        receipt = dict(cli.load_receipt(EXAMPLE_RECEIPT))
        receipt["verdict"] = "FAIL"
        self.assertEqual(cli.verify_sar_receipt(receipt)["integrity"], "FAIL")


class EntryPointTests(unittest.TestCase):
    def test_main_is_callable(self) -> None:
        self.assertTrue(callable(cli.main))


if __name__ == "__main__":
    unittest.main()
