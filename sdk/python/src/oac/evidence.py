"""Observations and evidence verdicts (spec 8.5): what the decision was, and whether someone else saw the effect."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from oac import consent, mandate, shapes, undo
from oac.errors import OACError
from oac.jws import KeySet, SigningKey, sign, token_digest, verify
from oac.receipts import TYP as RECEIPT_TYP
from oac.receipts import check_semantics, independent

TYP = "oac-observation+jws"
# what each authority kind is signed as, and the check of its fields
_AUTHORITY: dict[str, tuple[str, Callable[[Any], Any]]] = {
    "consent": (consent.TYP, shapes.consent),
    "mandate": (mandate.TYP, shapes.mandate),
    "undo": (undo.TYP, shapes.undo_request),
}


def make_observation(*, key: SigningKey, iss: str, sub: str, executor: str, receipt_token: str, effect: str, now: int,
                     subject: str | None = None, route: str | None = None, vantage: str | None = None) -> str:
    """A reader other than the executor says it saw (or did not see) the effect of this receipt."""
    doc = {"oac": shapes.VERSION, "type": "observation", "iss": iss, "sub": sub, "executor": executor,
           "receipt": token_digest(receipt_token), "effect": effect, "iat": now}
    doc |= {k: v for k, v in (("subject", subject), ("route", route), ("vantage", vantage)) if v is not None}
    return sign(shapes.observation(doc), key, TYP)


def _observed(r: Mapping[str, Any], token: str, observations: Sequence[str], keys: KeySet | None, executor: str) -> list[dict[str, Any]]:
    if observations and keys is None:
        raise OACError("malformed", "observations need the observer's keys")
    out = []
    for t in observations:
        o = verify(t, keys, TYP)  # type: ignore[arg-type]
        shapes.observation(o)
        independent(o["iss"], executor, "observer_not_independent")
        if o["sub"] != r["sub"]:
            raise OACError("subject_mismatch")
        if o["executor"] != executor:
            raise OACError("executor_mismatch")
        if o["receipt"] != token_digest(token):
            raise OACError("receipt_mismatch", "the observation is about another receipt")
        out.append(o)
    return out


def _binds(r: Mapping[str, Any], p: Mapping[str, Any]) -> bool:
    kind, ref = r["authority"]["kind"], r["authority"]["ref"]
    if kind == "consent":
        return p["jti"] == ref and any(i["preview"] == r.get("preview") and i["action"] == r["action"] for i in p["items"])
    if kind == "mandate":
        return p["id"] == ref
    return p["jti"] == ref and p["receipt"] == r.get("undoes")


def _decision(r: Mapping[str, Any], token: str | None, keys: KeySet | None) -> str:
    a = r["authority"]
    if a["kind"] == "tier":
        return "tier"
    if token is None:
        return "unverified"
    if keys is None:
        raise OACError("malformed", "an authority token needs its signer's keys")
    if token_digest(token) != a["digest"]:
        raise OACError("authority_mismatch", "this is not the token the receipt names")
    typ, check = _AUTHORITY[a["kind"]]
    p = check(verify(token, keys, typ))
    if not _binds(r, p):
        raise OACError("authority_mismatch", "the token does not cover this action and preview")
    return "bound"


def _effect(outcome: str, observed: Sequence[Mapping[str, Any]]) -> str:
    seen = [o for o in observed if o["effect"] == "seen"]
    if len({o["subject"] for o in seen if "subject" in o}) > 1:
        return "duplicate"
    if seen:
        return "contradicted" if outcome == "failed" else "observed"
    if outcome == "failed":
        return "absent"
    return "not_observed" if outcome == "ok" and any(o["effect"] == "not_seen" for o in observed) else "cannot_establish"


def assess(
    receipt_token: str,
    *,
    keys: KeySet,
    executor: str,
    observations: Sequence[str] = (),
    observer_keys: KeySet | None = None,
    authority_token: str | None = None,
    authority_keys: KeySet | None = None,
) -> dict[str, Any]:
    """Route, decision and effect of one receipt as three separate answers, then a verdict (spec 8.5)."""
    r = verify(receipt_token, keys, RECEIPT_TYP)
    shapes.receipt(r)
    check_semantics(r)
    if r["iss"] != executor:
        raise OACError("chain_issuer")
    effect = _effect(r["outcome"], _observed(r, receipt_token, observations, observer_keys, executor))
    decision = _decision(r, authority_token, authority_keys)
    if effect in ("not_observed", "contradicted", "duplicate"):
        verdict = "fail"
    else:
        verdict = "pass" if decision != "unverified" and effect in ("observed", "absent") else "cannot_establish"
    return {"route": r.get("route"), "decision": decision, "effect": effect, "verdict": verdict}
