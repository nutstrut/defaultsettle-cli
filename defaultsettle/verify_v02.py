"""Offline verifier for Default Settlement receipts, profile family
``settlement-witness-verified-v0.2*`` / ``receipt_version: "0.2-candidate"``.

Normative contract: ``specs/default-settlement-v02-verification/SPEC.md`` in the
Morpheus repository. Cross-language contract: the shared JSON vectors beside it.

Design rules (see SPEC.md):

* Pure and deterministic. No network, no clock, no filesystem access, no
  issuance, no evaluator re-run. Input: a receipt and a trust registry (both
  already-parsed JSON values). Output: a JSON-compatible result dict.
* RECEIPT VALIDITY is separate from ISSUER VERDICT. A cryptographically valid
  receipt whose verdict is FAIL or INDETERMINATE is still ``receipt_valid: true``.
* Signed property states are reported as signed; ``unknown`` is never promoted.
* Everything not covered by the signature is reported as unsigned and never
  influences validity.
* ``0.2-candidate`` is an explicit versioned contract. It is not aliased,
  normalised, or treated as a final identifier.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CONTRACT_ID = "ds-v02-verification-contract/1"
RECEIPT_VERSION = "0.2-candidate"
SIG_ALG = "Ed25519"
KEY_USE = "sar_settlement_witness_signing"

GENERIC_PROFILE = "settlement-witness-verified-v0.2"
COUNTERPARTY_BOUND_PROFILE = "settlement-witness-verified-v0.2-counterparty-bound"

_GENERIC_CORE = (
    "receipt_profile",
    "receipt_version",
    "sig_alg",
    "verdict",
    "reason_code",
    "properties",
    "verification_basis",
    "verifier_kid",
    "ts",
)
PROFILE_CORE_FIELDS = {
    GENERIC_PROFILE: _GENERIC_CORE,
    COUNTERPARTY_BOUND_PROFILE: _GENERIC_CORE + ("counterparty",),
}

BASIS_FIELDS = (
    "evaluator_id",
    "evaluator_version",
    "evaluation_profile",
    "policy_ref",
    "condition_digest",
    "evidence_profile",
    "evidence_digest",
    "request_id",
    "evaluated_at",
)
SIGNABLE_VERDICTS = ("PASS", "FAIL", "INDETERMINATE")
PROPERTY_STATES = ("pass", "fail", "unknown")
REQUIRED_PROPERTIES = (
    "declared_condition_satisfied",
    "evidence_digest_binding",
    "runtime_execution_established",
    "payment_finality_established",
    "legal_finality_established",
)
VERDICT_TO_CONDITION_STATE = {"PASS": "pass", "FAIL": "fail", "INDETERMINATE": "unknown"}
STATE_TO_BOUNDARY = {"pass": "established", "fail": "contradicted", "unknown": "not_established"}

# Property -> the claim it would establish if (and only if) it were signed `pass`.
_GATED_CLAIMS = {
    "runtime_execution_established": "runtime_execution",
    "payment_finality_established": "payment_finality",
    "legal_finality_established": "legal_finality",
}
# Never implied by any receipt, whatever it signs.
_ALWAYS_NOT_IMPLIED = (
    "current_admissibility",
    "external_effect",
    "general_agent_safety",
    "endorsement",
    "certification",
)

# Stable rejection code -> status name used by the pre-existing candidate
# artifact_verifier (None where the candidate verifier had no separate status).
LEGACY_STATUS = {
    "MALFORMED_JSON": None,
    "DUPLICATE_KEY": None,
    "MALFORMED_RECEIPT": "REJECTED_MALFORMED",
    "NOT_A_V02_RECEIPT": "REJECTED_NOT_CANDIDATE",
    "UNSUPPORTED_PROFILE": "REJECTED_NOT_CANDIDATE",
    "UNSUPPORTED_SIG_ALG": "REJECTED_NOT_CANDIDATE",
    "UNSUPPORTED_RECEIPT_VERSION": "REJECTED_NOT_CANDIDATE",
    "MISSING_FIELD": "REJECTED_MALFORMED",
    "FIELD_TYPE_INVALID": "REJECTED_MALFORMED",
    "VERDICT_INVALID": "REJECTED_MALFORMED",
    "PROPERTIES_INVALID": "REJECTED_MALFORMED",
    "VERIFICATION_BASIS_INVALID": "REJECTED_MALFORMED",
    "COUNTERPARTY_INVALID": "REJECTED_MALFORMED",
    "VERDICT_PROPERTY_INCONSISTENT": None,
    "CANONICALIZATION_FAILED": "REJECTED_MALFORMED",
    "UNKNOWN_KEY": "REJECTED_UNKNOWN_KEY",
    "KEY_NOT_ACTIVE": None,
    "KEY_USE_NOT_AUTHORIZED": None,
    "PROFILE_NOT_AUTHORIZED": "REJECTED_PROFILE_NOT_AUTHORIZED",
    "RECEIPT_ID_MALFORMED": "REJECTED_MALFORMED",
    "RECEIPT_ID_MISMATCH": "REJECTED_RECEIPT_ID_MISMATCH",
    "SIGNATURE_MALFORMED": "REJECTED_MALFORMED",
    "SIGNATURE_INVALID": "REJECTED_INVALID_SIGNATURE",
}

NON_CLAIMS = (
    "Receipt validity means the signature, receipt_id and signed fields are intact and the "
    "issuer key is trusted for this profile. It is not an endorsement of the issuer verdict.",
    "The issuer verdict is the issuer's signed statement about a declared condition against "
    "the bound evidence digest; this verifier does not re-evaluate it.",
    "Fields outside the signed core (including _unsigned and payment) are not covered by the "
    "signature and are reported only as unsigned_fields_present.",
    "Properties signed unknown are not established by this receipt; unknown is never false.",
)

_RECEIPT_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
# Every SHA-256 digest string in the contract (receipt_id, condition_digest, evidence_digest) is
# exactly `sha256:` + 64 lowercase hex characters, matched against the WHOLE string. Length alone
# is not the rule: code-point length (Python) and UTF-16 length (JavaScript) disagree on astral text.
_DIGEST_RE = _RECEIPT_ID_RE
# Normative nesting cap, enforced identically in every implementation (SPEC section 3a).
# A container (object or array) at nesting depth > MAX_JSON_DEPTH is rejected; the outermost
# container is depth 1.
MAX_JSON_DEPTH = 64
# Integer tokens longer than this are never exact safe integers; see parse_receipt_text.
_MAX_EXACT_INT_TOKEN = 18
_SIG_BODY_RE = re.compile(r"[A-Za-z0-9_-]{86}")
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]+")


class TrustPolicyError(ValueError):
    """The supplied trust registry is unusable. Raised to the calling layer;
    verification never proceeds against a broken trust root."""


class _Reject(Exception):
    def __init__(self, code: str, detail: str, **extra: Any) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail
        self.extra = extra


# ---------------------------------------------------------------------------
# RFC 8785 canonicalization (subset sufficient for signed cores, fail-closed)
# ---------------------------------------------------------------------------

def _u16sorted(items):
    """Sort strings by UTF-16 code unit, the same order RFC 8785 uses for keys, so every
    implementation (Python, JavaScript, ...) lists names identically."""
    return sorted(items, key=lambda x: x.encode("utf-16-be", "surrogatepass"))


class CanonicalizationError(ValueError):
    pass


def _jcs_string(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def _jcs_value(v: Any, depth: int = 0) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, int):
        if abs(v) >= 2**53:
            raise CanonicalizationError("integer outside the I-JSON safe range")
        return str(v)
    if isinstance(v, float):
        if not math.isfinite(v) or v != math.floor(v) or abs(v) >= 2**53:
            raise CanonicalizationError("non-integral or non-finite number is not supported")
        return str(int(v))
    if isinstance(v, (list, dict)) and depth + 1 > MAX_JSON_DEPTH:
        raise CanonicalizationError("nesting exceeds the maximum depth")
    if isinstance(v, list):
        return "[" + ",".join([_jcs_value(i, depth + 1) for i in v]) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise CanonicalizationError("object key is not a string")
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join([_jcs_string(k) + ":" + _jcs_value(val, depth + 1) for k, val in items]) + "}"
    raise CanonicalizationError("unsupported JSON value type")


def canonicalize(value: Any) -> bytes:
    try:
        text = _jcs_value(value)
    except RecursionError as exc:  # defensive: the explicit depth cap should always fire first
        raise CanonicalizationError("nesting exceeds the interpreter limit") from exc
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:  # lone surrogate
        raise CanonicalizationError("string is not valid Unicode") from exc


# ---------------------------------------------------------------------------
# Strict base64url
# ---------------------------------------------------------------------------

def decode_base64url_strict(body: str) -> bytes:
    """Unpadded base64url only. Rejects any character outside the alphabet
    (the stdlib decoder silently discards them), padding, and non-canonical
    trailing bits."""
    if not isinstance(body, str) or not _B64URL_RE.fullmatch(body) or len(body) % 4 == 1:
        raise ValueError("not strict unpadded base64url")
    raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != body:
        raise ValueError("non-canonical base64url")
    return raw


# ---------------------------------------------------------------------------
# JSON loading with duplicate-key rejection
# ---------------------------------------------------------------------------

class DuplicateKeyError(ValueError):
    pass


def _no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise DuplicateKeyError(k)
        out[k] = v
    return out


def _reject_constant(name):
    raise ValueError("non-finite JSON constant " + name)


def _json_depth_exceeds(text: str, limit: int) -> bool:
    """True if the text nests containers deeper than `limit`. String-aware, linear, and
    syntax-agnostic (it never needs the text to be valid JSON). Identical in every
    implementation, so a depth rejection is the same everywhere."""
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "[" or ch == "{":
            depth += 1
            if depth > limit:
                return True
        elif ch == "]" or ch == "}":
            depth -= 1
    return False


def _parse_int_token(token: str) -> Any:
    """Integer tokens beyond 18 characters are not safe integers whatever their value and
    would otherwise trip CPython's integer-string conversion limit (a parse failure JavaScript
    does not share). They become a float, as JavaScript's Number() does: such a value is
    rejected inside the signed core (CANONICALIZATION_FAILED) and inert in unsigned fields."""
    return int(token) if len(token) <= _MAX_EXACT_INT_TOKEN else float(token)


def parse_receipt_text(text: str) -> tuple[Any, Optional[tuple[str, str]]]:
    """Returns (value, None) or (None, (code, detail))."""
    if _json_depth_exceeds(text, MAX_JSON_DEPTH):
        return None, ("MALFORMED_JSON", "input is not valid JSON")
    try:
        return (
            json.loads(
                text,
                object_pairs_hook=_no_dupes,
                parse_constant=_reject_constant,
                parse_int=_parse_int_token,
            ),
            None,
        )
    except DuplicateKeyError:
        return None, ("DUPLICATE_KEY", "receipt JSON contains a duplicate object key")
    except (ValueError, RecursionError):
        return None, ("MALFORMED_JSON", "input is not valid JSON")


# ---------------------------------------------------------------------------
# Trust index
# ---------------------------------------------------------------------------

def build_trust_index(registry: Any) -> dict[str, dict]:
    """Registry (the ``/.well-known/sar-keys.json`` schema) -> kid -> entry
    with a decoded ``pubkey`` (or None if the key material is unusable)."""
    if not isinstance(registry, dict) or not isinstance(registry.get("keys"), list):
        raise TrustPolicyError("registry must be an object with a 'keys' list")
    index: dict[str, dict] = {}
    for entry in registry["keys"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("kid"), str) or not entry["kid"]:
            raise TrustPolicyError("registry entry without a string kid")
        kid = entry["kid"]
        if kid in index:
            raise TrustPolicyError("duplicate kid in registry")
        pub_x = pub_hex = None
        try:
            if "x" in entry:
                pub_x = decode_base64url_strict(entry["x"])
            if "public_key_hex" in entry:
                if not re.fullmatch(r"[0-9a-f]{64}", str(entry["public_key_hex"])):
                    raise ValueError("bad hex")
                pub_hex = bytes.fromhex(entry["public_key_hex"])
        except (ValueError, TypeError):
            pub_x, pub_hex = None, None
            pubkey = None
        else:
            if pub_x is not None and pub_hex is not None and pub_x != pub_hex:
                pubkey = None  # inconsistent material: fail closed
            else:
                pubkey = pub_x if pub_x is not None else pub_hex
            if pubkey is not None and len(pubkey) != 32:
                pubkey = None
        profiles = entry.get("profiles")
        index[kid] = {
            "pubkey": pubkey,
            "status": entry.get("status"),
            "use": entry.get("use"),
            "profiles": frozenset(profiles) if isinstance(profiles, list) else frozenset(),
        }
    return index


def _key_currency(status: Any) -> str:
    if status == "active":
        return "current"
    if status == "retired":
        return "historical"
    return "unstated"  # statusless legacy entry


# ---------------------------------------------------------------------------
# Result construction
# ---------------------------------------------------------------------------

CHECKS = (
    "structure",
    "profile_and_version",
    "required_fields",
    "signed_field_types",
    "verdict_property_consistency",
    "key_lookup",
    "key_status",
    "key_use",
    "profile_authorization",
    "receipt_id_binding",
    "signature_encoding",
    "signature",
)
# Which check a rejection code fails at.
_CODE_TO_CHECK = {
    "MALFORMED_JSON": "structure",
    "DUPLICATE_KEY": "structure",
    "MALFORMED_RECEIPT": "structure",
    "NOT_A_V02_RECEIPT": "profile_and_version",
    "UNSUPPORTED_PROFILE": "profile_and_version",
    "UNSUPPORTED_SIG_ALG": "profile_and_version",
    "UNSUPPORTED_RECEIPT_VERSION": "profile_and_version",
    "MISSING_FIELD": "required_fields",
    "COUNTERPARTY_INVALID": "signed_field_types",
    "FIELD_TYPE_INVALID": "signed_field_types",
    "VERDICT_INVALID": "signed_field_types",
    "PROPERTIES_INVALID": "signed_field_types",
    "VERIFICATION_BASIS_INVALID": "signed_field_types",
    "VERDICT_PROPERTY_INCONSISTENT": "verdict_property_consistency",
    "CANONICALIZATION_FAILED": "receipt_id_binding",
    "UNKNOWN_KEY": "key_lookup",
    "KEY_NOT_ACTIVE": "key_status",
    "KEY_USE_NOT_AUTHORIZED": "key_use",
    "PROFILE_NOT_AUTHORIZED": "profile_authorization",
    "RECEIPT_ID_MALFORMED": "receipt_id_binding",
    "RECEIPT_ID_MISMATCH": "receipt_id_binding",
    "SIGNATURE_MALFORMED": "signature_encoding",
    "SIGNATURE_INVALID": "signature",
}


def _checks(failed_code: Optional[str]) -> list[dict]:
    if failed_code is None:
        return [{"check": c, "result": "pass"} for c in CHECKS]
    failed = _CODE_TO_CHECK[failed_code]
    out, hit = [], False
    for c in CHECKS:
        if hit:
            out.append({"check": c, "result": "not_run"})
        elif c == failed:
            out.append({"check": c, "result": "fail"})
            hit = True
        else:
            out.append({"check": c, "result": "pass"})
    return out


def _str_or_none(v: Any) -> Optional[str]:
    return v if isinstance(v, str) else None


def _empty_result(receipt: Any, provenance: Optional[dict]) -> dict:
    r = receipt if isinstance(receipt, dict) else {}
    return {
        "verifier": {
            "contract": CONTRACT_ID,
            "supported_receipt_version": RECEIPT_VERSION,
            "network_access": False,
        },
        "receipt_valid": False,
        "receipt": {
            "receipt_version": _str_or_none(r.get("receipt_version")),
            "receipt_profile": _str_or_none(r.get("receipt_profile")),
            "receipt_id": _str_or_none(r.get("receipt_id")),
            "computed_receipt_id": None,
        },
        "checks": [],
        "issuer": {
            "kid": _str_or_none(r.get("verifier_kid")),
            "key_known": False,
            "key_status": None,
            "key_use": None,
            "key_currency": None,
            "profile_authorized": None,
            "trust_snapshot": dict(provenance) if provenance else None,
        },
        "issuer_verdict": None,
        "signed_properties": None,
        "boundary": None,
        "unsigned_fields_present": [],
        "rejection": None,
        "non_claims": list(NON_CLAIMS),
    }


def _boundary(props: dict) -> dict:
    mapped = {name: STATE_TO_BOUNDARY[props[name]] for name in _u16sorted(props)}
    not_implied = list(_ALWAYS_NOT_IMPLIED)
    for prop, claim in _GATED_CLAIMS.items():
        if props.get(prop) != "pass":
            not_implied.append(claim)
    return {
        "properties": mapped,
        "established": _u16sorted(n for n, s in mapped.items() if s == "established"),
        "contradicted": _u16sorted(n for n, s in mapped.items() if s == "contradicted"),
        "not_established": _u16sorted(n for n, s in mapped.items() if s == "not_established"),
        "not_implied": _u16sorted(not_implied),
    }


# ---------------------------------------------------------------------------
# The verifier
# ---------------------------------------------------------------------------

def _nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and v.strip() != ""


def verify_receipt(
    receipt: Any,
    trust_index: dict[str, dict],
    provenance: Optional[dict] = None,
) -> dict:
    """Verify one parsed receipt against a trust index built by
    :func:`build_trust_index`. Never raises on receipt content."""
    result = _empty_result(receipt, provenance)
    try:
        _verify(receipt, trust_index, result)
    except _Reject as rej:
        rejection = {"code": rej.code, "detail": rej.detail, "legacy_status": LEGACY_STATUS[rej.code]}
        rejection.update(rej.extra)
        result["rejection"] = rejection
        result["checks"] = _checks(rej.code)
        result["receipt_valid"] = False
        result["issuer_verdict"] = None
        result["signed_properties"] = None
        result["boundary"] = None
    return result


def verify_receipt_text(text: str, registry: Any, provenance: Optional[dict] = None) -> dict:
    """Convenience: parse (duplicate-key strict) then verify."""
    index = build_trust_index(registry)
    value, err = parse_receipt_text(text)
    if err is not None:
        result = _empty_result(None, provenance)
        result["rejection"] = {"code": err[0], "detail": err[1], "legacy_status": None}
        result["checks"] = _checks(err[0])
        return result
    return verify_receipt(value, index, provenance)


def _verify(receipt: Any, trust_index: dict, result: dict) -> None:
    if not isinstance(receipt, dict):
        raise _Reject("MALFORMED_RECEIPT", "receipt is not a JSON object")

    profile = receipt.get("receipt_profile")
    if not isinstance(profile, str):
        raise _Reject("NOT_A_V02_RECEIPT", "receipt does not declare a receipt_profile")
    core_fields = PROFILE_CORE_FIELDS.get(profile)
    if core_fields is None:
        raise _Reject("UNSUPPORTED_PROFILE", "receipt_profile is not a supported v0.2 profile")
    result["unsigned_fields_present"] = _u16sorted(
        k for k in receipt if k not in core_fields and k not in ("receipt_id", "sig")
    )
    if receipt.get("sig_alg") != SIG_ALG:
        raise _Reject("UNSUPPORTED_SIG_ALG", "sig_alg is not Ed25519")
    # Literal, exact match. "0.2-candidate" is not aliased to or normalised from anything.
    if receipt.get("receipt_version") != RECEIPT_VERSION:
        raise _Reject("UNSUPPORTED_RECEIPT_VERSION", "receipt_version is not exactly '0.2-candidate'")

    missing = [f for f in core_fields + ("receipt_id", "sig") if f not in receipt]
    if missing:
        raise _Reject("MISSING_FIELD", "required field(s) absent", fields=missing)

    verdict = receipt["verdict"]
    if not isinstance(verdict, str) or verdict not in SIGNABLE_VERDICTS:
        raise _Reject("VERDICT_INVALID", "verdict is outside the signable domain")

    for f in ("reason_code", "verifier_kid", "ts"):
        if not _nonempty_str(receipt[f]):
            raise _Reject("FIELD_TYPE_INVALID", "signed string field missing or empty", fields=[f])

    props = receipt["properties"]
    if not isinstance(props, dict):
        raise _Reject("PROPERTIES_INVALID", "properties is not an object")
    absent = [p for p in REQUIRED_PROPERTIES if p not in props]
    if absent:
        raise _Reject("PROPERTIES_INVALID", "required property absent", fields=absent)
    bad = _u16sorted(n for n, s in props.items() if not isinstance(s, str) or s not in PROPERTY_STATES)
    if bad:
        raise _Reject("PROPERTIES_INVALID", "property state outside pass/fail/unknown", fields=bad)

    basis = receipt["verification_basis"]
    if not isinstance(basis, dict):
        raise _Reject("VERIFICATION_BASIS_INVALID", "verification_basis is not an object")
    missing_basis = [f for f in BASIS_FIELDS if f not in basis]
    if missing_basis:
        raise _Reject("VERIFICATION_BASIS_INVALID", "verification_basis field absent", fields=missing_basis)
    bad_basis = [f for f in BASIS_FIELDS if not _nonempty_str(basis[f])]
    for f in ("condition_digest", "evidence_digest"):
        v = basis[f]
        if f not in bad_basis and not _DIGEST_RE.fullmatch(v):
            bad_basis.append(f)
    if bad_basis:
        raise _Reject("VERIFICATION_BASIS_INVALID", "verification_basis field empty or malformed", fields=_u16sorted(bad_basis))

    if "counterparty" in core_fields and not _nonempty_str(receipt["counterparty"]):
        raise _Reject("COUNTERPARTY_INVALID", "counterparty-bound profile requires a non-empty counterparty")

    if props["declared_condition_satisfied"] != VERDICT_TO_CONDITION_STATE[verdict]:
        raise _Reject(
            "VERDICT_PROPERTY_INCONSISTENT",
            "verdict disagrees with declared_condition_satisfied",
        )

    core = {f: receipt[f] for f in core_fields}
    try:
        digest = hashlib.sha256(canonicalize(core)).digest()
    except CanonicalizationError:
        raise _Reject("CANONICALIZATION_FAILED", "signed core cannot be canonicalized") from None
    expected_id = "sha256:" + digest.hex()
    result["receipt"]["computed_receipt_id"] = expected_id

    kid = receipt["verifier_kid"]
    entry = trust_index.get(kid)
    if entry is None or entry["pubkey"] is None:
        raise _Reject("UNKNOWN_KEY", "verifier_kid is not in the pinned trust snapshot or its key material is unusable")
    issuer = result["issuer"]
    issuer["key_known"] = True
    issuer["key_status"] = entry["status"]
    issuer["key_use"] = entry["use"]
    issuer["key_currency"] = _key_currency(entry["status"])

    # Lifecycle: only active, retired (historical) and statusless legacy keys can
    # authenticate a receipt. reserved / withdrawn-before-activation / anything
    # else fails closed even though key material exists.
    if entry["status"] is not None and entry["status"] not in ("active", "retired"):
        raise _Reject("KEY_NOT_ACTIVE", "key lifecycle status does not permit signing authority")
    # A present `use` must be the settlement-witness signing use. Absent `use` is the
    # legacy (-01/-02/-03) shape; the profile gate below still applies to it.
    if entry["use"] is not None and entry["use"] != KEY_USE:
        raise _Reject("KEY_USE_NOT_AUTHORIZED", "key use is present and is not sar_settlement_witness_signing")
    if profile not in entry["profiles"]:
        issuer["profile_authorized"] = False
        raise _Reject("PROFILE_NOT_AUTHORIZED", "key is known but not authorized for this receipt_profile")
    issuer["profile_authorized"] = True

    rid = receipt["receipt_id"]
    if not isinstance(rid, str) or not _RECEIPT_ID_RE.fullmatch(rid):
        raise _Reject("RECEIPT_ID_MALFORMED", "receipt_id is not sha256:<64 lowercase hex>")
    if rid != expected_id:
        raise _Reject("RECEIPT_ID_MISMATCH", "receipt_id does not match the digest of the signed core")

    sig = receipt["sig"]
    if not isinstance(sig, str) or not sig.startswith("base64url:") or not _SIG_BODY_RE.fullmatch(sig[10:]):
        raise _Reject("SIGNATURE_MALFORMED", "sig is not base64url:<86 strict unpadded base64url characters>")
    try:
        sig_bytes = decode_base64url_strict(sig[10:])
    except ValueError:
        raise _Reject("SIGNATURE_MALFORMED", "sig is not canonical base64url") from None
    try:
        # Ed25519 is verified over the 32 SHA-256 digest bytes, not the canonical bytes.
        Ed25519PublicKey.from_public_bytes(entry["pubkey"]).verify(sig_bytes, digest)
    except (InvalidSignature, ValueError):
        raise _Reject("SIGNATURE_INVALID", "Ed25519 signature does not verify") from None

    result["receipt_valid"] = True
    result["checks"] = _checks(None)
    result["issuer_verdict"] = {"verdict": verdict, "reason_code": receipt["reason_code"]}
    result["signed_properties"] = {k: props[k] for k in _u16sorted(props)}
    result["boundary"] = _boundary(props)
