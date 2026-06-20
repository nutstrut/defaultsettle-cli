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


class SignatureAuthenticationTests(unittest.TestCase):
    def test_signed_receipt_passes_integrity_and_signature(self) -> None:
        receipt = cli.load_receipt(EXAMPLE_RECEIPT)
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_PASS)

    def test_fake_verifier_kid_fails_signature(self) -> None:
        receipt = dict(cli.load_receipt(EXAMPLE_RECEIPT))
        receipt["verifier_kid"] = "sar-prod-ed25519-99"
        # receipt_id is recomputed from the body, so integrity stays consistent
        # with the tampered kid; only signature authentication should fail.
        receipt["receipt_id"] = cli.compute_receipt_id(receipt)
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_FAIL)

    def test_fabricated_receipt_cannot_authenticate(self) -> None:
        # A fully fabricated receipt with a made-up kid: integrity can be made to
        # pass by recomputing the id, but signature authentication must fail.
        receipt = {
            "task_id_hash": "sha256:" + "ab" * 32,
            "verdict": "PASS",
            "confidence": 1.0,
            "reason_code": "SPEC_MATCH",
            "ts": "2026-06-20T00:00:00.000000Z",
            "verifier_kid": "totally-made-up-kid",
            "sig": "base64url:" + "A" * 86,
        }
        receipt["receipt_id"] = cli.compute_receipt_id(receipt)
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_FAIL)

    def test_invalid_signature_fails(self) -> None:
        receipt = dict(cli.load_receipt(EXAMPLE_RECEIPT))
        # Flip the signature to a valid-length but wrong value.
        receipt["sig"] = "base64url:" + "B" * 86
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_FAIL)

    def test_missing_signature_fails_for_signed_receipt(self) -> None:
        receipt = dict(cli.load_receipt(EXAMPLE_RECEIPT))
        del receipt["sig"]
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_FAIL)

    def test_sar_402_recorded_receipt_is_not_applicable(self) -> None:
        # A SAR-402 recorded receipt is not a signed SettlementWitness receipt:
        # no verifier_kid, no signature. Integrity is still checkable.
        receipt = {
            "task_id_hash": "sha256:" + "cd" * 32,
            "verdict": "RECORDED",
            "confidence": 1.0,
            "reason_code": "SAR-402",
            "ts": "2026-06-20T00:00:00.000000Z",
        }
        receipt["receipt_id"] = cli.compute_receipt_id(receipt)
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(
            result["signature_authentication"], cli.SIGNATURE_NOT_APPLICABLE
        )

    def test_sar_402_wrapper_receipt_is_not_applicable(self) -> None:
        receipt = {
            "receipt_id": "sha256:example",
            "receipt_type": "sar_402_settlement",
            "receipt": {
                "profile": "sar-402",
                "sar_type": "Settlement Attestation Receipt",
                "verification_mode": "record",
            },
        }
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["receipt_type"], "sar_402_settlement")
        self.assertEqual(result["receipt_id"], "sha256:example")
        self.assertEqual(result["integrity"], cli.SIGNATURE_NOT_APPLICABLE)
        self.assertEqual(
            result["signature_authentication"], cli.SIGNATURE_NOT_APPLICABLE
        )

    def test_parse_signature_accepts_prefixed_and_bare(self) -> None:
        receipt = cli.load_receipt(EXAMPLE_RECEIPT)
        prefixed = receipt["sig"]
        bare = prefixed[len("base64url:") :]
        self.assertEqual(cli.parse_signature(prefixed), cli.parse_signature(bare))


class EntryPointTests(unittest.TestCase):
    def test_main_is_callable(self) -> None:
        self.assertTrue(callable(cli.main))


if __name__ == "__main__":
    unittest.main()
