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
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SAR_402_CANONICAL = FIXTURES_DIR / "sar-402-canonical-demo.json"
SAR_402_TAMPERED = FIXTURES_DIR / "sar-402-tampered.json"


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

    def test_sar_402_canonical_payload_detected_as_recorded_evidence(self) -> None:
        receipt = cli.load_receipt(SAR_402_CANONICAL)
        self.assertTrue(cli.is_sar_402_recorded(receipt))
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["artifact_type"], "sar_402_recorded_evidence")

    def test_sar_402_canonical_payload_integrity_passes(self) -> None:
        receipt = cli.load_receipt(SAR_402_CANONICAL)
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["computed_digest"], result["declared_digest"])

    def test_sar_402_tampered_payload_integrity_fails(self) -> None:
        receipt = cli.load_receipt(SAR_402_TAMPERED)
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "FAIL")
        self.assertNotEqual(result["computed_digest"], result["declared_digest"])

    def test_sar_402_signature_authentication_is_not_applicable(self) -> None:
        receipt = cli.load_receipt(SAR_402_CANONICAL)
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(
            result["signature_authentication"], cli.SIGNATURE_NOT_APPLICABLE
        )
        tampered_result = cli.verify_sar_receipt(cli.load_receipt(SAR_402_TAMPERED))
        self.assertEqual(
            tampered_result["signature_authentication"], cli.SIGNATURE_NOT_APPLICABLE
        )

    def test_sar_402_old_synthetic_wrapper_shape_is_not_detected(self) -> None:
        # The old receipt_type/nested-receipt wrapper never matched any real
        # artifact; detection must key off the real top-level schema_id/profile.
        receipt = {
            "receipt_id": "sha256:example",
            "receipt_type": "sar_402_settlement",
            "receipt": {
                "profile": "sar-402",
                "sar_type": "Settlement Attestation Receipt",
                "verification_mode": "record",
            },
        }
        self.assertFalse(cli.is_sar_402_recorded(receipt))

    def test_parse_signature_accepts_prefixed_and_bare(self) -> None:
        receipt = cli.load_receipt(EXAMPLE_RECEIPT)
        prefixed = receipt["sig"]
        bare = prefixed[len("base64url:") :]
        self.assertEqual(cli.parse_signature(prefixed), cli.parse_signature(bare))


class SharedFixtureParityTests(unittest.TestCase):
    """Verify the shared MCP/SettlementWitness SAR v0.1 fixtures.

    These fixtures carry ``sar_version`` and are signed by kid-01/kid-02/kid-03
    — exactly the cases the core-field allow-list and expanded key registry
    fix are meant to cover.
    """

    def test_pass_fixture_verifies(self) -> None:
        receipt = cli.load_receipt(FIXTURES_DIR / "sar-v0.1-pass.json")
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_PASS)

    def test_fail_fixture_verifies(self) -> None:
        receipt = cli.load_receipt(FIXTURES_DIR / "sar-v0.1-fail.json")
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_PASS)
        self.assertEqual(result["verdict"], "FAIL")

    def test_indeterminate_fixture_verifies(self) -> None:
        receipt = cli.load_receipt(FIXTURES_DIR / "sar-v0.1-indeterminate.json")
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_PASS)
        self.assertEqual(result["verdict"], "INDETERMINATE")

    def test_current_kid03_fixture_verifies(self) -> None:
        receipt = cli.load_receipt(FIXTURES_DIR / "sar-v0.1-current-kid03.json")
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_PASS)
        self.assertEqual(result["verifier_kid"], "sar-prod-ed25519-03")

    def test_tampered_fixture_fails(self) -> None:
        receipt = cli.load_receipt(FIXTURES_DIR / "tampered-receipt.json")
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "FAIL")
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_FAIL)


class EntryPointTests(unittest.TestCase):
    def test_main_is_callable(self) -> None:
        self.assertTrue(callable(cli.main))


class RegistryLifecycleTests(unittest.TestCase):
    """Phase 7 registry refresh: lifecycle classification test matrix.

    Covers current-active (-05), historical-retired (-03), documented-
    non-operational-duplicate (-02), reserved, unknown, and wrong-profile
    keys, plus the offline/zero-egress and snapshot-hash guarantees.
    """

    def test_bundled_snapshot_hash_matches_canonical_registry(self) -> None:
        # Independently verified 2026-07-19 byte-identical across
        # /home/ubuntu/settlement-witness/sar-keys.json,
        # /var/www/html/.well-known/sar-keys.json, and
        # https://defaultverifier.com/.well-known/sar-keys.json.
        from defaultsettle import registry_snapshot as rs

        self.assertEqual(
            rs.snapshot_sha256(),
            "2da5285f458af9f3369e5baddd953164834d961161c87c9594b823ce251a4f6b",
        )
        self.assertEqual(rs.SNAPSHOT_SHA256, rs.snapshot_sha256())

    def test_snapshot_hash_mismatch_fails_closed(self) -> None:
        from defaultsettle import registry_snapshot as rs

        # examples/receipt.json is not the registry at all, so loading it as
        # a registry snapshot must fail closed rather than silently proceed.
        with self.assertRaises(rs.RegistrySnapshotError):
            rs.RegistrySnapshot(str(FIXTURES_DIR.parent.parent / "examples" / "receipt.json"))

    def test_snapshot_hash_mismatch_against_pinned_value_fails_closed(self) -> None:
        from defaultsettle import registry_snapshot as rs

        snap = rs.load_default_snapshot()
        with self.assertRaises(rs.RegistrySnapshotError):
            snap.verify_pinned_hash(expected="0" * 64)

    def test_current_kid05_is_active_current_production_signer(self) -> None:
        receipt = cli.load_receipt(FIXTURES_DIR / "sar-v0.1-current-kid05.json")
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_PASS)
        self.assertEqual(result["signer_lifecycle_status"], "active")
        self.assertTrue(result["trusted_current_production_signer"])
        self.assertTrue(result["trusted_historical_signer"])

    def test_historical_kid03_is_retired_not_active(self) -> None:
        receipt = cli.load_receipt(FIXTURES_DIR / "sar-v0.1-current-kid03.json")
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_PASS)
        self.assertEqual(result["signer_lifecycle_status"], "retired")
        self.assertFalse(result["trusted_current_production_signer"])
        self.assertTrue(result["trusted_historical_signer"])

    def test_kid02_classification_is_documented_non_operational_duplicate(self) -> None:
        # -02's own registry entry (no independent operational evidence,
        # identical public-key bytes to -03) must classify as
        # documented_non_operational_duplicate per the D4 shared-identity
        # clarification (2026-07-12), and must never be reported as an
        # independently active/current production signer.
        classification = cli.classify_signer("sar-prod-ed25519-02")
        self.assertTrue(classification.present)
        self.assertTrue(classification.is_documented_non_operational_duplicate)
        self.assertEqual(
            classification.lifecycle_label, "documented_non_operational_duplicate"
        )
        self.assertFalse(classification.is_current_production_signer)
        self.assertFalse(classification.is_historically_verifiable)

    def test_kid02_signature_verifies_but_is_never_reported_as_active(self) -> None:
        # verifier_kid is part of the signed core, so a real -02-attributed
        # signature can only exist if something actually signed with
        # verifier_kid="sar-prod-ed25519-02" -- no such receipt has ever
        # existed (0 of 553 ledger records reference this kid, per the
        # registry's own note). To exercise the "signature valid but not an
        # independently active signer" path end-to-end without any
        # production private key, build a fixture-only registry snapshot
        # with a deterministic, clearly-marked test-only duplicate key pair
        # and sign a fixture-only payload with it locally.
        import tempfile

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from defaultsettle import registry_snapshot as rs

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        import base64

        pub_raw = public_key.public_bytes_raw() if hasattr(public_key, "public_bytes_raw") else None
        if pub_raw is None:
            from cryptography.hazmat.primitives import serialization

            pub_raw = public_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        pub_x = base64.urlsafe_b64encode(pub_raw).rstrip(b"=").decode("ascii")

        fixture_registry = {
            "keys": [
                {
                    "kid": "fixture-only-duplicate-primary",
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": pub_x,
                    "use": "sar_settlement_witness_signing",
                    "status": "retired",
                },
                {
                    "kid": "fixture-only-duplicate-secondary",
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": pub_x,
                    "use": "sar_settlement_witness_signing",
                    "note": "TEST-ONLY FIXTURE. classification=documented_non_operational_duplicate "
                    "(mirrors the real sar-prod-ed25519-02/-03 relationship for test purposes only).",
                },
            ]
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(fixture_registry, f)
            fixture_path = f.name

        try:
            fixture_snapshot = rs.RegistrySnapshot(fixture_path)
            primary = fixture_snapshot.classify("fixture-only-duplicate-primary")
            secondary = fixture_snapshot.classify("fixture-only-duplicate-secondary")
            self.assertEqual(primary.lifecycle_label, "retired")
            self.assertEqual(secondary.lifecycle_label, "documented_non_operational_duplicate")
            self.assertFalse(secondary.is_current_production_signer)

            original_snapshot = cli._REGISTRY_SNAPSHOT
            cli._REGISTRY_SNAPSHOT = fixture_snapshot
            try:
                receipt = {
                    "task_id_hash": "sha256:" + "11" * 32,
                    "verdict": "PASS",
                    "confidence": 1.0,
                    "reason_code": "SPEC_MATCH",
                    "ts": "2026-07-19T00:00:00.000000Z",
                    "verifier_kid": "fixture-only-duplicate-secondary",
                }
                receipt["receipt_id"] = cli.compute_receipt_id(receipt)
                digest = bytes.fromhex(receipt["receipt_id"].split(":", 1)[1])
                signature = private_key.sign(digest)
                receipt["sig"] = "base64url:" + base64.urlsafe_b64encode(signature).rstrip(b"=").decode(
                    "ascii"
                )
                result = cli.verify_sar_receipt(receipt)
                self.assertEqual(result["integrity"], "PASS")
                self.assertEqual(result["signature_authentication"], cli.SIGNATURE_PASS)
                self.assertEqual(
                    result["signer_lifecycle_status"], "documented_non_operational_duplicate"
                )
                self.assertFalse(result["trusted_current_production_signer"])
                self.assertFalse(result["trusted_historical_signer"])
            finally:
                cli._REGISTRY_SNAPSHOT = original_snapshot
        finally:
            import os as _os

            _os.unlink(fixture_path)

    def test_reserved_key_not_accepted_as_current_operational_signer(self) -> None:
        classification = cli.classify_signer("sar-prod-ed25519-04")
        self.assertTrue(classification.present)
        self.assertEqual(classification.lifecycle_label, "reserved")
        self.assertFalse(classification.is_current_production_signer)

    def test_unknown_key_fails_closed(self) -> None:
        classification = cli.classify_signer("sar-prod-ed25519-99")
        self.assertFalse(classification.present)
        self.assertEqual(classification.lifecycle_label, "unknown")
        receipt = dict(cli.load_receipt(FIXTURES_DIR / "sar-v0.1-current-kid05.json"))
        receipt["verifier_kid"] = "sar-prod-ed25519-99"
        receipt["receipt_id"] = cli.compute_receipt_id(receipt)
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_FAIL)

    def test_wrong_profile_key_rejected(self) -> None:
        # A key registered for a different signing profile (SAR-402 recording
        # attribution) must never authenticate a SAR settlement-witness
        # receipt, regardless of its own lifecycle status.
        classification = cli.classify_signer("defaultverifier-recording-ed25519-2")
        self.assertTrue(classification.present)
        self.assertFalse(classification.profile_ok)
        self.assertEqual(classification.lifecycle_label, "wrong_profile")
        self.assertFalse(classification.is_current_production_signer)

    def test_tampered_payload_under_current_signer_fails_signature(self) -> None:
        receipt = dict(cli.load_receipt(FIXTURES_DIR / "sar-v0.1-current-kid05.json"))
        receipt["verdict"] = "FAIL"
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "FAIL")
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_FAIL)

    def test_tampered_signature_under_current_signer_fails(self) -> None:
        receipt = dict(cli.load_receipt(FIXTURES_DIR / "sar-v0.1-current-kid05.json"))
        receipt["sig"] = "base64url:" + "Z" * 86
        result = cli.verify_sar_receipt(receipt)
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["signature_authentication"], cli.SIGNATURE_FAIL)

    def test_output_reports_snapshot_hash_and_freshness_limitation(self) -> None:
        receipt = cli.load_receipt(FIXTURES_DIR / "sar-v0.1-current-kid05.json")
        result = cli.verify_sar_receipt(receipt)
        self.assertIn(result["registry_snapshot_sha256"], result["offline_verification_note"])
        self.assertIn("does not confirm the live registry", result["offline_verification_note"])

    def test_verification_makes_no_network_calls(self) -> None:
        import socket

        def _blocked(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("verify_sar_receipt attempted network access")

        original_socket = socket.socket
        socket.socket = _blocked  # type: ignore[assignment]
        try:
            receipt = cli.load_receipt(FIXTURES_DIR / "sar-v0.1-current-kid05.json")
            result = cli.verify_sar_receipt(receipt)
            self.assertEqual(result["signature_authentication"], cli.SIGNATURE_PASS)
        finally:
            socket.socket = original_socket


if __name__ == "__main__":
    unittest.main()
