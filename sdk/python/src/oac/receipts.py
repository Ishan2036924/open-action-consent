"""Receipts (spec section 8): the executor's signed record of each action, chained per person. `prev` is the digest of
the previous receipt's whole token, so a dropped, reordered or edited receipt breaks the chain."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from oac import shapes
from oac.errors import OACError
from oac.jws import KeySet, SigningKey, sign, token_digest, verify

TYP = "oac-receipt+jws"


def make_receipt(*, key: SigningKey, payload: Mapping[str, Any]) -> str:
    doc = {"oac": shapes.VERSION, "type": "receipt", **payload}
    check_semantics(shapes.receipt(doc))
    return sign(doc, key, TYP)


def check_semantics(r: Mapping[str, Any]) -> None:
    """Rules a schema cannot say: D never runs; B always carries a live Undo (except an undo receipt itself); C names a
    Consent, a Mandate or a signed Undo request."""
    tier, kind, undo = r["tier"], r["authority"]["kind"], r["undo"]
    if tier == "D":
        raise OACError("receipt_invalid", "a tier D action never runs")
    if (kind != "tier") != ("ref" in r["authority"]):
        raise OACError("receipt_invalid", "consent, mandate and undo authority carry a ref; tier carries none")
    if kind == "tier" and tier not in ("A", "B"):
        raise OACError("receipt_invalid", "tier C needs a consent, mandate or undo authority")
    if undo["kind"] == "none" and ("until" in undo or "token" in undo):
        raise OACError("receipt_invalid", "undo none carries no window or token")
    if undo["kind"] != "none" and r["outcome"] == "ok" and "until" not in undo:
        raise OACError("receipt_invalid", "a reversible action says until when")
    if tier == "B" and kind != "undo" and r["outcome"] == "ok" and (undo["kind"] != "native" or "token" not in undo):
        raise OACError("receipt_invalid", "tier B needs a native undo token")
    if kind == "undo" and "undoes" not in r:
        raise OACError("receipt_invalid", "an undo receipt names what it undoes")


def verify_chain(
    tokens: Sequence[str], *, keys: KeySet, executor: str, sub: str | None = None
) -> list[dict[str, Any]]:
    """Verify an export: every signature, every link, contiguous seq. A chain may start mid-way (seq > 1) when it is
    an export from a known point; seq 1 has prev null."""
    out: list[dict[str, Any]] = []
    for i, token in enumerate(tokens):
        r = verify(token, keys, TYP)
        shapes.receipt(r)
        check_semantics(r)
        if r["iss"] != executor:
            raise OACError("chain_issuer")
        if (sub or (out[0]["sub"] if out else r["sub"])) != r["sub"]:
            raise OACError("subject_mismatch")
        if i == 0:
            if (r["seq"] == 1) != (r["prev"] is None):
                raise OACError("chain_broken", "only seq 1 has no prev")
        else:
            if r["seq"] != out[-1]["seq"] + 1:
                raise OACError("chain_seq")
            if r["prev"] != token_digest(tokens[i - 1]):
                raise OACError("chain_broken")
        out.append(r)
    return out
