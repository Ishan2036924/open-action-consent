"""Undo requests (spec section 8.3): the person asks the executor to take one receipt's action back. `native` restores
the prior state inside the window; `compensate` runs a new action (cancel, refund) that needs its own verified Consent,
whose action names the receipt; `none` cannot be undone. A receipt is undone at most once."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any

from oac import shapes
from oac.consent import MAX_S, NonceStore, check_time, new_nonce
from oac.errors import OACError
from oac.jws import KeySet, SigningKey, sign, token_digest, verify
from oac.preview import action_digest
from oac.receipts import TYP as RECEIPT_TYP
from oac.receipts import check_semantics

TYP = "oac-undo+jws"


def make_undo(
    *,
    key: SigningKey,
    iss: str,
    sub: str,
    aud: str,
    receipt_token: str,
    mode: str,
    now: int,
    ttl: int = 300,
    jti: str | None = None,
    consent: str | None = None,
) -> str:
    doc: dict[str, Any] = {
        "oac": shapes.VERSION,
        "type": "undo",
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "jti": jti or new_nonce(),
        "iat": now,
        "exp": now + ttl,
        "receipt": token_digest(receipt_token),
        "mode": mode,
    }
    if consent is not None:
        doc["consent"] = consent
    return sign(shapes.undo_request(doc), key, TYP)


def check_undo(
    token: str,
    *,
    keys: KeySet,
    executor: str,
    receipt_token: str,
    receipt_keys: KeySet,
    now: int,
    nonces: NonceStore,
    undone: Collection[str] = (),
    compensation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """`undone` = token digests of receipts this executor already undid. For `compensate`, `compensation` is
    {"consent": <payload returned by verify_consent>, "action": <the compensating action>}, whose args must carry
    "undoes": <this receipt's token digest>."""
    p = verify(token, keys, TYP)
    shapes.undo_request(p)
    if p["aud"] != executor:
        raise OACError("wrong_audience")
    check_time(p, now, MAX_S)
    if p["receipt"] != token_digest(receipt_token):
        raise OACError("receipt_mismatch")
    r = verify(receipt_token, receipt_keys, RECEIPT_TYP)
    shapes.receipt(r)
    check_semantics(r)
    if r["iss"] != executor:
        raise OACError("receipt_mismatch", "the receipt is another executor's")
    if r["sub"] != p["sub"]:
        raise OACError("subject_mismatch")
    if r["outcome"] != "ok" or r["undo"]["kind"] == "none":
        raise OACError("not_reversible")
    if r["undo"]["kind"] != p["mode"]:
        raise OACError("undo_mode_mismatch")
    if now > r["undo"]["until"]:
        raise OACError("undo_window_closed")
    if p["receipt"] in undone:
        raise OACError("already_undone")
    if p["mode"] == "compensate":
        if "consent" not in p:
            raise OACError("malformed", "a compensating undo names the consent for its new action")
        c = compensation or {}
        consent, act = c.get("consent"), c.get("action")
        if (
            not isinstance(consent, Mapping)
            or not isinstance(act, Mapping)
            or consent.get("jti") != p["consent"]
            or consent.get("sub") != p["sub"]
            or not isinstance(act.get("args"), Mapping)
            or act["args"].get("undoes") != p["receipt"]
            or action_digest(act) not in [i["action"] for i in consent.get("items", [])]
        ):
            raise OACError("compensation_mismatch", "the compensating consent does not cover undoing this receipt")
    if not nonces.use_once(p["jti"], p["exp"]):
        raise OACError("replay")
    return p
