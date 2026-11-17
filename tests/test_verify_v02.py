"""Tests for the offline Default Settlement v0.2-candidate verifier.

Driven by the shared language-neutral vector suite (tests/fixtures/v02/vectors.json,
a byte copy of the normative suite in the Morpheus repository). No network.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from defaultsettle import cli
from defaultsettle import verify_v02 as v02

FIX = Path(__file__).resolve().parent / "fixtures" / "v02"
SUITE = json.loads((FIX / "vectors.json").read_text(encoding="utf-8"))
PKG = Path(cli.__file__).resolve().parent


def _registry(policy_name: str):
    pol = SUITE["trust_policies"][policy_name]
    if "registry" in pol:
        return pol["registry"]
    return json.loads((FIX / "sar-keys-snapshot.json").read_text(encoding="utf-8"))


def _run_case(case):
    pol = SUITE["trust_policies"][case["trust_policy"]]
    index = v02.build_trust_index(_registry(case["trust_policy"]))
    if "receipt_raw" in case:
        value, err = v02.parse_receipt_text(case["receipt_raw"])
        if err:
            res = v02._empty_result(None, pol["provenance"])
            res["rejection"] = {"code": err[0], "detail": err[1], "legacy_status": None}
            res["checks"] = v02._checks(err[0])
            return res
        return v02.verify_receipt(value, index, pol["provenance"])
    return v02.verify_receipt(case["receipt"], index, pol["provenance"])


def _case(cid):
    return next(c for c in SUITE["cases"] if c["id"] == cid)


class SharedVectorTests(unittest.TestCase):
    def test_every_vector_matches_expected_result(self) -> None:
        self.assertGreaterEqual(len(SUITE["cases"]), 100)
        for case in SUITE["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(_run_case(case), case["expected_result"])

    def test_every_vector_matches_hand_written_expectation(self) -> None:
        for case in SUITE["cases"]:
            with self.subTest(case=case["id"]):
                res, e = _run_case(case), case["expect"]
                self.assertEqual(res["receipt_valid"], e["receipt_valid"])
                self.assertEqual(res["rejection"]["code"] if res["rejection"] else None, e["rejection_code"])
                if e["receipt_valid"]:
                    self.assertEqual(res["issuer_verdict"], e["issuer_verdict"])
                    self.assertEqual(res["signed_properties"], e["signed_properties"])
                    self.assertEqual(res["unsigned_fields_present"], e["unsigned_fields_present"])
                    self.assertEqual(res["issuer"]["key_currency"], e["key_currency"])
                else:
                    self.assertIsNone(res["issuer_verdict"])
                    self.assertIsNone(res["signed_properties"])
                    self.assertIsNone(res["boundary"])


class SecurityTests(unittest.TestCase):
    def test_real_06_receipt_verifies_offline(self) -> None:
        res = _run_case(_case("valid-real-06-indeterminate"))
        self.assertTrue(res["receipt_valid"])
        self.assertEqual(res["issuer"]["kid"], "sar-prod-ed25519-06")
        self.assertEqual(res["issuer"]["key_currency"], "current")

    def test_validity_is_separate_from_verdict(self) -> None:
        for cid, verdict in (("valid-pass", "PASS"), ("valid-fail", "FAIL"), ("valid-indeterminate", "INDETERMINATE")):
            res = _run_case(_case(cid))
            self.assertTrue(res["receipt_valid"])
            self.assertEqual(res["issuer_verdict"]["verdict"], verdict)
            self.assertNotIn("status", res)

    def test_pass_with_unknown_execution_does_not_claim_execution(self) -> None:
        b = _run_case(_case("valid-pass-execution-payment-legal-unknown"))["boundary"]
        self.assertEqual(b["properties"]["declared_condition_satisfied"], "established")
        for p in ("runtime_execution_established", "payment_finality_established", "legal_finality_established"):
            self.assertEqual(b["properties"][p], "not_established")
        for claim in ("runtime_execution", "payment_finality", "legal_finality", "current_admissibility",
                      "external_effect", "general_agent_safety", "endorsement", "certification"):
            self.assertIn(claim, b["not_implied"])

    def test_signed_pass_removes_only_that_claim_from_not_implied(self) -> None:
        b = _run_case(_case("valid-pass-runtime-signed-pass"))["boundary"]
        self.assertNotIn("runtime_execution", b["not_implied"])
        self.assertIn("payment_finality", b["not_implied"])

    def test_junk_base64_is_rejected_where_stdlib_would_accept(self) -> None:
        case = _case("sig-prefix-junk")
        body = case["receipt"]["sig"][10:]
        # The stdlib decoder silently discards the junk: this is the defect strict decoding closes.
        self.assertEqual(len(base64.urlsafe_b64decode(body + "==")), 64)
        self.assertEqual(_run_case(case)["rejection"]["code"], "SIGNATURE_MALFORMED")

    def test_unsigned_mutation_does_not_affect_validity(self) -> None:
        for cid in ("unsigned-mutate-_unsigned", "unsigned-add-payment", "unsigned-real-06-mutate-payment"):
            self.assertTrue(_run_case(_case(cid))["receipt_valid"], cid)

    def test_unknown_and_unauthorized_keys_fail_closed(self) -> None:
        self.assertEqual(_run_case(_case("key-unknown-kid"))["rejection"]["code"], "UNKNOWN_KEY")
        self.assertEqual(_run_case(_case("key-other-profile-only"))["rejection"]["code"], "PROFILE_NOT_AUTHORIZED")
        self.assertEqual(_run_case(_case("prod-key-sar-prod-ed25519-04"))["rejection"]["code"], "KEY_NOT_ACTIVE")

    def test_candidate_version_is_not_aliased(self) -> None:
        self.assertEqual(_run_case(_case("version-0.2-not-aliased"))["rejection"]["code"], "UNSUPPORTED_RECEIPT_VERSION")

    def test_verification_never_opens_a_socket(self) -> None:
        def boom(*a, **k):
            raise AssertionError("network access attempted")

        with mock.patch.object(socket, "socket", boom), mock.patch.object(socket, "create_connection", boom):
            for case in SUITE["cases"]:
                _run_case(case)

    def test_core_module_has_no_network_or_io_imports(self) -> None:
        src = (PKG / "verify_v02.py").read_text(encoding="utf-8")
        for banned in ("urllib", "socket", "requests", "http", "subprocess", "open(", "os.environ"):
            self.assertNotIn(banned, src)


class TrustSnapshotTests(unittest.TestCase):
    def test_bundled_snapshot_matches_provenance_and_suite_copy(self) -> None:
        raw = (PKG / "sar-keys-v02-snapshot.json").read_bytes()
        prov = json.loads((PKG / "sar-keys-v02-snapshot.provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(hashlib.sha256(raw).hexdigest(), prov["sha256"])
        self.assertEqual(raw, (FIX / "sar-keys-snapshot.json").read_bytes())
        self.assertEqual(prov["sha256"], SUITE["trust_policies"]["production"]["provenance"]["sha256"])

    def test_snapshot_registers_06_for_exactly_the_two_v02_profiles(self) -> None:
        keys = {k["kid"]: k for k in json.loads((PKG / "sar-keys-v02-snapshot.json").read_text())["keys"]}
        k06 = keys["sar-prod-ed25519-06"]
        self.assertEqual(k06["status"], "active")
        self.assertEqual(sorted(k06["profiles"]), [v02.GENERIC_PROFILE, v02.COUNTERPARTY_BOUND_PROFILE])
        self.assertEqual(keys["sar-prod-ed25519-04"]["status"], "withdrawn-before-activation")

    def test_tampered_snapshot_is_fatal(self) -> None:
        with mock.patch.object(Path, "read_bytes", return_value=b'{"keys": []}'):
            with self.assertRaises(RuntimeError):
                cli.load_v02_trust()

    def test_broken_registry_is_a_trust_policy_error(self) -> None:
        for bad in (None, {}, {"keys": [{"kid": "a"}, {"kid": "a"}]}, {"keys": [{}]}):
            with self.assertRaises(v02.TrustPolicyError):
                v02.build_trust_index(bad)


class CliTests(unittest.TestCase):
    def _run(self, text: str, registry=None):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "r.json"
            path.write_text(text, encoding="utf-8")
            args = cli.build_parser().parse_args(["verify-v02", str(path)])
            out, err = io.StringIO(), io.StringIO()
            patcher = (
                mock.patch.object(cli, "load_v02_trust", return_value=registry)
                if registry
                else contextlib.nullcontext()
            )
            with patcher, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.handle_verify_v02(args)
        return code, out.getvalue(), err.getvalue()

    def _test_registry(self):
        pol = SUITE["trust_policies"]["test"]
        return pol["registry"], pol["provenance"]

    def test_real_06_receipt_exit_0_with_pinned_snapshot(self) -> None:
        code, out, _ = self._run(json.dumps(_case("valid-real-06-indeterminate")["receipt"]))
        self.assertEqual(code, 0)
        res = json.loads(out)
        self.assertTrue(res["receipt_valid"])
        self.assertEqual(res["issuer_verdict"]["verdict"], "INDETERMINATE")
        self.assertEqual(res["issuer"]["trust_snapshot"]["sha256"], SUITE["trust_policies"]["production"]["provenance"]["sha256"])

    def test_valid_pass_fail_indeterminate_all_exit_0(self) -> None:
        for cid in ("valid-pass", "valid-fail", "valid-indeterminate"):
            code, out, _ = self._run(json.dumps(_case(cid)["receipt"]), self._test_registry())
            self.assertEqual(code, 0, cid)
            self.assertTrue(json.loads(out)["receipt_valid"])

    def test_invalid_signature_exit_1_and_stdout_is_json_only(self) -> None:
        code, out, err = self._run(json.dumps(_case("sig-corrupted-valid-encoding")["receipt"]), self._test_registry())
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["rejection"]["code"], "SIGNATURE_INVALID")
        self.assertIn("SIGNATURE_INVALID", err)

    def test_production_snapshot_rejects_test_key_receipts(self) -> None:
        code, out, _ = self._run(json.dumps(_case("valid-pass")["receipt"]))
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["rejection"]["code"], "UNKNOWN_KEY")

    def test_unreadable_input_exit_2(self) -> None:
        args = cli.build_parser().parse_args(["verify-v02", "/nonexistent/receipt.json"])
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.handle_verify_v02(args), 2)
        code, out, _ = self._run("{not json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["rejection"]["code"], "MALFORMED_JSON")

    def test_duplicate_key_exit_1(self) -> None:
        code, out, _ = self._run(_case("canon-duplicate-key-raw")["receipt_raw"], self._test_registry())
        self.assertEqual(code, 1)

    def test_existing_verify_subcommand_still_parses(self) -> None:
        self.assertTrue(callable(cli.build_parser().parse_args(["verify", "x"]).func))


if __name__ == "__main__":
    unittest.main()
