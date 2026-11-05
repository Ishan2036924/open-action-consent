"""Receipts (spec 8): the executor's signed record of each action, chained per person."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from oac import shapes
from oac.errors import OACError
from oac.jws import KeySet, SigningKey, sign, token_digest, verify

TYP = "oac-receipt+jws"
SEAL_TYP = "oac-seal+jws"


def make_receipt(*, key: SigningKey, payload: Mapping[str, Any]) -> str:
    doc = {"oac": shapes.VERSION, "type": "receipt", **payload}
    check_semantics(shapes.receipt(doc))
    return sign(doc, key, TYP)


def check_semantics(r: Mapping[str, Any]) -> None:
    """Receipt rules a schema cannot express."""
    tier, kind, undo = r["tier"], r["authority"]["kind"], r["undo"]
    if tier == "D":
        raise OACError("receipt_invalid", "a tier D action never runs")
    for name in ("ref", "digest"):
        if (kind != "tier") != (name in r["authority"]):
            raise OACError("receipt_invalid", f"consent, mandate and undo authority carry a {name}; tier carries none")
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


def make_seal(*, key: SigningKey, iss: str, sub: str, executor: str, seq: int, head_token: str, now: int) -> str:
    """The person's signer vouches that this person's chain at `executor` reached `seq` with this receipt."""
    doc = {"oac": shapes.VERSION, "type": "seal", "iss": iss, "sub": sub, "executor": executor, "seq": seq,
           "head": token_digest(head_token), "iat": now}
    return sign(shapes.seal(doc), key, SEAL_TYP)


def verify_chain(
    tokens: Sequence[str],
    *,
    keys: KeySet,
    executor: str,
    sub: str | None = None,
    seals: Sequence[str] = (),
    seal_keys: KeySet | None = None,
) -> list[dict[str, Any]]:
    """Verify an export of receipts and any seals over it. It may start after seq 1."""
    out: list[dict[str, Any]] = []
    done: set[tuple[str, str]] = set()
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
        if "occurrence" in r and r["outcome"] == "ok":
            if (r["tool"], r["occurrence"]) in done:
                raise OACError("duplicate_occurrence", "the same occurrence ran twice")
            done.add((r["tool"], r["occurrence"]))
        out.append(r)
    if seals:
        check_seals(out, tokens, seals=seals, seal_keys=seal_keys, executor=executor)
    return out


def check_seals(chain: Sequence[Mapping[str, Any]], tokens: Sequence[str], *, seals: Sequence[str],
                seal_keys: KeySet | None, executor: str) -> None:
    if seal_keys is None:
        raise OACError("malformed", "seals need the signer's keys")
    by_seq = {r["seq"]: tokens[i] for i, r in enumerate(chain)}
    for token in seals:
        s = verify(token, seal_keys, SEAL_TYP)
        shapes.seal(s)
        if chain and s["sub"] != chain[0]["sub"]:
            raise OACError("subject_mismatch")
        if s["executor"] != executor or s["seq"] not in by_seq or s["head"] != token_digest(by_seq[s["seq"]]):
            raise OACError("seal_mismatch", "the seal does not match this chain")
