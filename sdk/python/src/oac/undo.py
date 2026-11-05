"""Undo requests (spec section 8.3): the person asks the executor to take one receipt's action back. `native` restores
the prior state inside the window; `compensate` runs a new action (cancel, refund) that needs its own Consent, named
here; `none` cannot be undone and is refused."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from oac import shapes
from oac.consent import MAX_S, NonceStore, check_time, new_nonce
from oac.errors import OACError
from oac.jws import KeySet, SigningKey, sign, token_digest, verify
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
) -> dict[str, Any]:
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
    if p["mode"] == "compensate" and "consent" not in p:
        raise OACError("malformed", "a compensating undo names the consent for its new action")
    if nonces.seen(p["jti"]):
        raise OACError("replay")
    nonces.use(p["jti"], p["exp"])
    return p
