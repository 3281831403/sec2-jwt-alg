import base64
import hashlib
import hmac
import json

from engine.jwtv.verify import jwt_batch


_HASHES = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _secret(key: dict) -> bytes:
    text = key["k"]
    return base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))


def _key(kid: str, secret: bytes) -> dict:
    return {"kid": kid, "kty": "oct", "k": _b64(secret)}


def _policy(keyring: list[dict], algorithms: list[str] | None = None) -> dict:
    algorithms = algorithms or ["HS256"]
    return {
        "algorithms": algorithms,
        "allow_none": False,
        "key_types": {alg: "symmetric" for alg in algorithms},
        "keyring": keyring,
    }


def _make_token(
    payload: dict,
    key: dict,
    alg: str = "HS256",
    header_raw: bytes | None = None,
    payload_raw: bytes | None = None,
) -> str:
    if header_raw is None:
        header_raw = json.dumps(
            {"alg": alg, "typ": "JWT", "kid": key["kid"]},
            separators=(",", ":"),
        ).encode("utf-8")
    if payload_raw is None:
        payload_raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    header = _b64(header_raw)
    body = _b64(payload_raw)
    signing_input = (header + "." + body).encode("ascii")
    if alg == "none":
        signature = ""
    else:
        signature = _b64(
            hmac.new(_secret(key), signing_input, _HASHES[alg]).digest()
        )
    return header + "." + body + "." + signature


def test_public_valid_token_is_accepted():
    key = _key("k1", b"public-one-secret")
    policy = _policy([key])
    header = b'{"typ": "JWT", "alg": "HS256", "kid": "k1"}'
    token = _make_token({"sub": "alice"}, key, header_raw=header)

    outcome = jwt_batch([token], policy)

    assert outcome["results"][0]["ok"] is True


def test_public_unsigned_token_is_rejected():
    key = _key("k1", b"public-two-secret")
    policy = _policy([key])
    token = _make_token({"sub": "alice"}, key, alg="none")

    outcome = jwt_batch([token], policy)

    assert outcome["results"][0]["ok"] is False


def test_public_algorithm_outside_policy_is_rejected():
    key = _key("k1", b"public-three-secret")
    policy = _policy([key], algorithms=["HS256"])
    token = _make_token({"sub": "alice"}, key, alg="HS512")

    outcome = jwt_batch([token], policy)

    assert outcome["results"][0]["ok"] is False


def test_public_tampered_payload_is_rejected():
    key = _key("k1", b"public-four-secret")
    policy = _policy([key])
    payload = {"sub": "alice", "role": "reader"}
    token = _make_token(payload, key)
    header, _body, signature = token.split(".")
    other_payload = _b64(json.dumps(payload, indent=1).encode("utf-8"))
    tampered = header + "." + other_payload + "." + signature

    outcome = jwt_batch([tampered], policy)

    assert outcome["results"][0]["ok"] is False


def test_public_batch_tokens_are_independent():
    first_key = _key("k1", b"public-five-alpha")
    second_key = _key("k2", b"public-five-beta")
    policy = _policy([first_key, second_key])
    first = _make_token({"sub": "alice"}, first_key)
    second = _make_token({"sub": "bob"}, second_key)

    outcome = jwt_batch([first, second], policy)

    assert [item["ok"] for item in outcome["results"]] == [True, True]