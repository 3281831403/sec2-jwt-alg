"""JWT verification primitives.

The module intentionally keeps the public surface small: every function is a
single policy decision or a parsing step.  A policy is a mapping with an
algorithm whitelist, an allow_none flag, a key-type map, and a keyring.  A
keyring is a list of key mappings.  Symmetric keys use kty oct and carry the
secret in k as base64url bytes.  RSA keys use kty RSA and carry n and e as
base64url unsigned big-endian integers.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from typing import Any


_HS_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

_RSA_SHA256_DIGEST_INFO = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    if not isinstance(segment, str):
        raise ValueError("base64url segment must be text")
    try:
        raw = segment.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("base64url segment must be ascii") from exc
    padded = raw + b"=" * ((4 - len(raw) % 4) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64url segment") from exc


def _decode_json_object(segment: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(_b64url_decode(segment).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"invalid {label} encoding") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _is_symmetric_key(key: Any) -> bool:
    if isinstance(key, (bytes, bytearray, str)):
        return True
    return isinstance(key, dict) and key.get("kty") == "oct"


def _is_asymmetric_key(key: Any) -> bool:
    return isinstance(key, dict) and key.get("kty") == "RSA"


def _secret_bytes(key: Any) -> bytes:
    if isinstance(key, (bytes, bytearray)):
        return bytes(key)
    if isinstance(key, str):
        return key.encode("utf-8")
    if isinstance(key, dict) and key.get("kty") == "oct":
        material = key.get("k")
        if isinstance(material, str):
            return _b64url_decode(material)
    raise ValueError("a symmetric key is required")


def _key_integer(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("invalid RSA integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int.from_bytes(_b64url_decode(value), "big")
    raise ValueError("invalid RSA integer")


def _rsa_verify(signing_input: bytes, signature: bytes, key: Any) -> bool:
    if not isinstance(key, dict) or key.get("kty") != "RSA":
        return False
    try:
        modulus = _key_integer(key.get("n"))
        exponent = _key_integer(key.get("e"))
    except (TypeError, ValueError):
        return False
    if modulus <= 0 or exponent <= 0:
        return False
    width = (modulus.bit_length() + 7) // 8
    if width < len(_RSA_SHA256_DIGEST_INFO) + 32 + 11:
        return False
    if len(signature) != width:
        return False
    encoded = int.from_bytes(signature, "big")
    if encoded >= modulus:
        return False
    recovered = pow(encoded, exponent, modulus).to_bytes(width, "big")
    digest = hashlib.sha256(signing_input).digest()
    padding = b"\xff" * (width - len(_RSA_SHA256_DIGEST_INFO) - len(digest) - 3)
    expected = b"\x00\x01" + padding + b"\x00" + _RSA_SHA256_DIGEST_INFO + digest
    return hmac.compare_digest(recovered, expected)


def split_token(text: str) -> dict[str, Any]:
    """Split a compact token and decode its header and payload."""
    if not isinstance(text, str) or not text:
        raise ValueError("token must be non-empty text")
    segments = text.split(".")
    if len(segments) != 3:
        raise ValueError("token must contain exactly header, payload and signature")
    header_b64 = segments[0]
    payload_b64 = segments[1]
    signature_b64 = segments[2] if len(segments) > 2 else ""
    if not header_b64 or not payload_b64:
        raise ValueError("token header and payload must be present")
    header = _decode_json_object(header_b64, "header")
    payload = _decode_json_object(payload_b64, "payload")
    try:
        signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("token segments must be ascii") from exc
    return {
        "header_b64": header_b64,
        "payload_b64": payload_b64,
        "signature_b64": signature_b64,
        "signing_input": signing_input,
        "header": header,
        "payload": payload,
    }


def check_alg(header: dict[str, Any], policy: dict[str, Any]) -> bool:
    """Return whether the token algorithm is the one the policy permits."""
    if not isinstance(header, dict) or not isinstance(policy, dict):
        return False
    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        return False
    if alg.lower() == "none":
        return False
    algorithms = policy.get("algorithms")
    if not isinstance(algorithms, (list, tuple, set)):
        return False
    return alg in algorithms


def check_none(alg: str) -> bool:
    """Return whether an algorithm is a real, signed algorithm."""
    return isinstance(alg, str) and alg.lower() != "none"


def check_key_type(alg: str, key: Any) -> bool:
    """Return whether key material is compatible with the algorithm."""
    if not isinstance(alg, str):
        return False
    if alg in _HS_ALGORITHMS:
        return _is_symmetric_key(key)
    if alg == "RS256":
        return _is_asymmetric_key(key)
    return False


def verify_signature(parts: dict[str, Any], key: Any, alg: str) -> bool:
    """Verify a signature over the token parts using the supplied key."""
    if not isinstance(parts, dict) or not isinstance(alg, str):
        return False
    if alg.lower() == "none":
        return False
    signature_b64 = parts.get("signature_b64")
    if not isinstance(signature_b64, str) or not signature_b64:
        return False
    try:
        signature = _b64url_decode(signature_b64)
    except ValueError:
        return False
    signing_input = parts.get("signing_input")
    if not isinstance(signing_input, (bytes, bytearray)):
        return False
    signing_input = bytes(signing_input)
    if alg in _HS_ALGORITHMS:
        if not _is_symmetric_key(key):
            return False
        try:
            secret = _secret_bytes(key)
        except ValueError:
            return False
        expected = hmac.new(secret, signing_input, _HS_ALGORITHMS[alg]).digest()
        return hmac.compare_digest(expected, signature)
    if alg == "RS256":
        if not _is_asymmetric_key(key):
            return False
        return _rsa_verify(signing_input, signature, key)
    return False


def check_kid(header: dict[str, Any], keyring: list[dict[str, Any]]) -> dict[str, Any]:
    """Resolve the key identifier in the header to exactly one key."""
    if not isinstance(keyring, (list, tuple)) or not keyring:
        raise ValueError("keyring must contain at least one key")
    kid = header.get("kid") if isinstance(header, dict) else None
    if not kid:
        if len(keyring) == 1:
            return keyring[0]
        raise ValueError("key identifier is required")
    matches = [
        key
        for key in keyring
        if isinstance(key, dict) and key.get("kid") == kid
    ]
    if not matches:
        raise ValueError("key identifier is unknown")
    if len(matches) > 1:
        raise ValueError("key identifier is ambiguous")
    return matches[0]


def validate_policy(policy: dict[str, Any]) -> list[str]:
    """Return human-readable problems with a verification policy."""
    if not isinstance(policy, dict):
        return ["policy must be a mapping"]
    issues: list[str] = []
    algorithms = policy.get("algorithms")
    if not isinstance(algorithms, (list, tuple, set)):
        algorithms = []
    if policy.get("allow_none") is True or "none" in algorithms:
        issues.append("none algorithm is allowed")
    key_types = policy.get("key_types")
    if not isinstance(key_types, dict) or not key_types:
        issues.append("key types are not constrained")
    else:
        for alg in algorithms:
            if alg not in key_types:
                issues.append("key type is not constrained for " + str(alg))
    return issues


def _expected_key_type(alg: str) -> str | None:
    if alg in _HS_ALGORITHMS:
        return "symmetric"
    if alg == "RS256":
        return "asymmetric"
    return None


_SYMMETRIC_ALIASES = {"symmetric", "oct", "secret", "hmac"}
_ASYMMETRIC_ALIASES = {"asymmetric", "rsa", "public"}


def _key_type_matches(policy_value: Any, expected: str) -> bool:
    if not isinstance(policy_value, str):
        return False
    normalized = policy_value.strip().lower()
    if expected == "symmetric":
        return normalized in _SYMMETRIC_ALIASES
    return normalized in _ASYMMETRIC_ALIASES


def jwt_batch(tokens: list[str], policy: dict[str, Any]) -> dict[str, Any]:
    """Validate tokens in one call while keeping per-token outcomes separate."""
    if isinstance(tokens, (str, bytes)) or tokens is None:
        raise TypeError("tokens must be an iterable of token strings")
    token_list = list(tokens)
    keyring = policy.get("keyring") if isinstance(policy, dict) else None
    if not isinstance(keyring, (list, tuple)):
        keyring = []
    policy_issues = validate_policy(policy)
    results: list[dict[str, Any]] = []
    if policy_issues:
        for index in range(len(token_list)):
            results.append(
                {"index": index, "ok": False, "kid": None, "error": "invalid policy"}
            )
    else:
        key_types = policy.get("key_types") if isinstance(policy, dict) else None
        for index, token in enumerate(token_list):
            kid: str | None = None
            try:
                parts = split_token(token)
                header = parts["header"]
                alg = header.get("alg")
                if not check_alg(header, policy):
                    raise ValueError("algorithm is not allowed")
                if not check_none(alg):
                    raise ValueError("unsigned token is not allowed")
                expected_type = _expected_key_type(alg)
                if expected_type is None:
                    raise ValueError("algorithm is not allowed")
                if isinstance(key_types, dict) and alg in key_types:
                    if not _key_type_matches(key_types[alg], expected_type):
                        raise ValueError("key type does not match algorithm")
                key = check_kid(header, keyring)
                if not check_key_type(alg, key):
                    raise ValueError("key type does not match algorithm")
                if not verify_signature(parts, key, alg):
                    raise ValueError("signature verification failed")
                if isinstance(key, dict) and isinstance(key.get("kid"), str):
                    kid = key["kid"]
                results.append({"index": index, "ok": True, "kid": kid, "error": None})
            except Exception as exc:  # noqa: BLE001 - batch reports per-token failure
                results.append(
                    {
                        "index": index,
                        "ok": False,
                        "kid": kid,
                        "error": str(exc) or type(exc).__name__,
                    }
                )
    accepted = [item["ok"] for item in results]
    return {
        "ok": all(accepted) if accepted else True,
        "results": results,
        "accepted": accepted,
        "rejected": [not item for item in accepted],
    }