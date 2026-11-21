"""Receipts (spec 8): the executor's signed record of each action, chained per person."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from oac import shapes
from oac.errors import OACError
from oac.jcs import parse
from oac.jws import KeySet, SigningKey, b64url_decode, sign, token_digest, verify
from oac.occurrence import scope

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
        if "occurrence" in r and r["outcome"] == "ok" and r["authority"]["kind"] != "undo":
            key = (scope(r), r["occurrence"])
            if key in done:
                raise OACError("duplicate_occurrence", "the same occurrence ran twice")
            done.add(key)
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


def independent(token: str, iss: str, executor: str, executor_keys: KeySet, code: str) -> None:
    """A witness of the executor must not be the executor, by name or by key (spec 8.4, 8.5)."""
    if iss == executor or executor_keys.get(parse(b64url_decode(token.split(".")[0]))["kid"]) is not None:
        raise OACError(code, "the executor cannot vouch for itself")


def _place(chain: Sequence[Mapping[str, Any]], tokens: Sequence[str], seq: int, head: str | None) -> bool:
    """Check a head claimed at `seq` against the export. True when the export reaches back to it."""
    if not chain or seq > chain[-1]["seq"]:
        raise OACError("chain_truncated", f"the export ends before seq {seq}")
    first = chain[0]["seq"]
    if seq < first - 1:
        return False
    want = chain[0]["prev"] if seq == first - 1 else token_digest(tokens[seq - first])
    if head is not None and head != want:
        raise OACError("seal_mismatch", f"the head at seq {seq} is not the one claimed")
    return True


def verify_export(
    tokens: Sequence[str],
    *,
    keys: KeySet,
    executor: str,
    sub: str | None = None,
    anchors: Sequence[str] = (),
    anchor_keys: KeySet | None = None,
    expect: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """verify_chain, then say how much of the export is proven complete by anchors the executor does not hold (spec 8.4)."""
    tokens, anchors = shapes.token_list(tokens, "tokens"), shapes.token_list(anchors, "anchors")
    chain = verify_chain(tokens, keys=keys, executor=executor, sub=sub)
    first, last = (chain[0]["seq"], chain[-1]["seq"]) if chain else (None, None)
    if anchors and anchor_keys is None:
        raise OACError("malformed", "anchors need the signer's keys")
    proven, start = None, first == 1
    for token in anchors:
        a = verify(token, anchor_keys, SEAL_TYP)
        shapes.seal(a)
        independent(token, a["iss"], executor, keys, "anchor_not_independent")
        if (sub or (chain[0]["sub"] if chain else a["sub"])) != a["sub"]:
            raise OACError("subject_mismatch")
        if a["executor"] != executor:
            raise OACError("seal_mismatch", "the anchor is for another executor")
        if _place(chain, tokens, a["seq"], a["head"]):
            start = start or a["seq"] == first - 1
            proven = max(proven or 0, a["seq"])
    if expect is not None:
        shapes.expectation(expect)
        _place(chain, tokens, expect["seq"], expect.get("head"))
    complete = proven is not None and proven == last and start
    reason = None if complete else "no_anchor" if proven is None else "unanchored_tail" if proven < last else "unanchored_start"
    return {"first": first, "last": last, "proven_to": proven, "status": "complete" if complete else "prefix", "reason": reason}
