"""Tests for the additive `verify-portable` subcommand and its bundled
Portable SAR verifier. Never touches the network. Does not import or
exercise the existing `verify` (wallet-bound) command path.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from defaultsettle import cli
from defaultsettle.portable_sar.portable_sar_verify import (
    PORTABLE_PROFILE_ID,
    STATUS_INVALID_SIGNATURE,
    STATUS_NOT_CANDIDATE,
    STATUS_PROFILE_NOT_AUTHORIZED,
    STATUS_RECEIPT_ID_MISMATCH,
    STATUS_UNKNOWN_KEY,
    STATUS_VERIFIED,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "defaultsettle" / "portable_sar" / "fixtures"
FIXTURES = json.loads((FIXTURES_DIR / "portable-sar-fixtures.json").read_text())
KEYS_PATH = FIXTURES_DIR / "portable-sar-fixture-keys.json"

EXPECTED = {
    "01_valid_portable": STATUS_VERIFIED,
    "02_unsigned_counterparty": STATUS_VERIFIED,
    "04_tampered_signed_field": STATUS_RECEIPT_ID_MISMATCH,
    "06_unknown_key": STATUS_UNKNOWN_KEY,
    "07_spoofed_key": STATUS_INVALID_SIGNATURE,
    "09_malformed_version": STATUS_NOT_CANDIDATE,
    "11_walletbound_presented_as_portable": STATUS_NOT_CANDIDATE,
    "12_metadata_grafted_walletbound": STATUS_PROFILE_NOT_AUTHORIZED,
}


class ParserTests(unittest.TestCase):
    def test_verify_portable_subcommand_parses(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["verify-portable", "receipt.json", "--keys", "keys.json"])
        self.assertTrue(callable(args.func))

    def test_existing_subcommands_unaffected(self) -> None:
        parser = cli.build_parser()
        for command in ("speedrun", "demo", "activate", "verify", "profile", "chain"):
            with self.subTest(command=command):
                if command in ("activate", "profile", "chain", "verify"):
                    args = parser.parse_args([command, "x"])
                else:
                    args = parser.parse_args([command])
                self.assertTrue(callable(args.func))


class VerifyPortableSubprocessTests(unittest.TestCase):
    def _run(self, fixture_name: str, tmp_path: Path) -> dict:
        receipt_path = tmp_path / "receipt.json"
        receipt_path.write_text(json.dumps(FIXTURES[fixture_name]))
        proc = subprocess.run(
            [sys.executable, "-m", "defaultsettle.cli", "verify-portable", str(receipt_path), "--keys", str(KEYS_PATH), "--json"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).resolve().parent.parent,
        )
        return json.loads(proc.stdout)

    def test_conformance_matrix(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            for name, expected_status in EXPECTED.items():
                with self.subTest(fixture=name):
                    result = self._run(name, tmp_path)
                    self.assertEqual(result["status"], expected_status, result.get("reason"))

    def test_verified_receipt_reports_no_wallet_binding(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            result = self._run("01_valid_portable", Path(td))
            self.assertEqual(result["status"], STATUS_VERIFIED)
            self.assertEqual(result["profile"], PORTABLE_PROFILE_ID)
            self.assertFalse(result["wallet_binding_attested"])


if __name__ == "__main__":
    unittest.main()
