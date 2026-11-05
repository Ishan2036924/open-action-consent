"""Edge cases the vectors do not reach: round trips, ES256, base64url strictness, nonce use, preview building."""

from __future__ import annotations

import pytest

from oac import (
    KeySet,
    MemoryNonces,
    OACError,
    build_preview,
    canonical,
    generate,
    make_consent,
    parse,
    sign,
    verify,
    verify_consent,
)
from oac.jws import b64url_decode

PROFILE = {
    "oac": "0.1",
    "type": "action-profile",
    "tool": "send_email",
    "effect": "send",
    "undo": {"kind": "none", "window_s": 0},
    "tier_floor": "A",
    "binds": {"to": "to", "title": "subject"},
}
ACTION = {"tool": "send_email", "args": {"to": ["sam@example.com"], "subject": "Hi", "body": "See you"}}


@pytest.mark.parametrize("alg", ["EdDSA", "ES256"])
def test_sign_verify_round_trip(alg: str) -> None:
    key = generate(alg)
    token = sign({"oac": "0.1", "n": 1}, key, "t+jws")
    assert verify(token, KeySet([key.jwk]), "t+jws") == {"oac": "0.1", "n": 1}
    with pytest.raises(OACError) as e:
        verify(token, KeySet([generate(alg).jwk]), "t+jws")
    assert e.value.code == "unknown_key"


def test_es256_token_rejected_by_ed25519_key_with_same_kid() -> None:
    ed, ec = generate("EdDSA"), generate("ES256")
    token = sign({"a": 1}, ec, "t")
    head, body, sig = token.split(".")
    forged = sign({"a": 1}, ed, "t").split(".")[0] + "." + body + "." + sig
    with pytest.raises(OACError) as e:
        verify(forged, KeySet([ed.jwk]), "t")
    assert e.value.code == "bad_signature"


def test_base64url_is_strict() -> None:
    for bad in ["a+b", "ab==", "a", "QR"]:  # wrong alphabet, padding, impossible length, non-zero pad bits
        with pytest.raises(OACError):
            b64url_decode(bad)


def test_canonical_refuses_floats_and_lone_surrogates() -> None:
    with pytest.raises(OACError):
        canonical({"a": 1.5})
    with pytest.raises(OACError):
        canonical({"a": "\ud800"})
    assert canonical(parse('{"z":1,"a":{"y":true}}')) == '{"a":{"y":true},"z":1}'


def test_full_flow_and_single_use_nonce() -> None:
    user, now = generate(), 1_800_000_000
    preview = build_preview(profile=PROFILE, action=ACTION, executor="ex", sub="p1", summary="Email sam", now=now)
    assert preview["fields"] == {"to": ["sam@example.com"], "title": "Hi"}
    token = make_consent(key=user, iss="signer", sub="p1", aud="ex", previews=[preview], now=now)
    nonces = MemoryNonces()
    kw = dict(keys=KeySet([user.jwk]), executor="ex", previews=[preview], actions=[ACTION],
              profiles={"send_email": PROFILE}, now=now + 5, nonces=nonces)
    assert verify_consent(token, **kw)["sub"] == "p1"
    with pytest.raises(OACError) as e:
        verify_consent(token, **kw)
    assert e.value.code == "replay"


def test_failed_check_does_not_burn_the_nonce() -> None:
    user, now = generate(), 1_800_000_000
    preview = build_preview(profile=PROFILE, action=ACTION, executor="ex", sub="p1", summary="Email sam", now=now)
    token = make_consent(key=user, iss="signer", sub="p1", aud="ex", previews=[preview], now=now)
    nonces = MemoryNonces()
    kw = dict(keys=KeySet([user.jwk]), executor="ex", previews=[preview], profiles={"send_email": PROFILE},
              now=now + 5, nonces=nonces)
    with pytest.raises(OACError):
        verify_consent(token, actions=[{**ACTION, "args": {**ACTION["args"], "to": ["x@evil.test"]}}], **kw)
    assert not nonces.seen(__import__("oac").parse(__import__("oac.jws", fromlist=["b64url_decode"]).b64url_decode(token.split(".")[1]))["jti"])
    verify_consent(token, actions=[ACTION], **kw)
