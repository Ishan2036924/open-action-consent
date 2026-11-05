"""Mandates (spec section 7): a standing, bounded, expiring permission. It can stand in for a Consent on tier C only;
it never covers tier D, never runs in a tainted run, and a pay tool needs caps and a payee list."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any

from oac import shapes
from oac.consent import check_time
from oac.errors import OACError
from oac.jcs import canonical
from oac.jws import KeySet, SigningKey, sign, verify
from oac.tiers import tier_for

TYP = "oac-mandate+jws"
MAX_S = 30 * 86400


def make_mandate(*, key: SigningKey, payload: Mapping[str, Any]) -> str:
    doc = {"oac": shapes.VERSION, "type": "mandate", **payload}
    return sign(shapes.mandate(doc), key, TYP)


def _recipient_ok(addr: str, allowed: list[str]) -> bool:
    """addr is one bare address (shapes); a rule is an exact address or "@domain", matched on the whole domain."""
    a = addr.lower()
    if "@" not in a:
        return False
    domain = a.rsplit("@", 1)[1]
    for rule in allowed:
        r = rule.lower()
        if r == a or (r.startswith("@") and r[1:] == domain):
            return True
    return False


def check_mandate(
    token: str,
    *,
    keys: KeySet,
    action: Mapping[str, Any],
    profile: Mapping[str, Any],
    holder: Mapping[str, Any],
    sub: str,
    now: int,
    tainted: bool,
    usage: Mapping[str, int] | None = None,
    revoked: Collection[str] = (),
    policy_floor: str = "A",
) -> dict[str, Any]:
    """`holder` and `sub` come from the executor's own authentication; `tainted` from the host runtime that saw what
    entered the run (never from the model), and it has no default on purpose; `usage` from the executor's own
    counters; `revoked` = ids the signer revoked or a later mandate superseded."""
    p = verify(token, keys, TYP)
    shapes.mandate(p)
    if canonical(p["holder"]) != canonical(holder):
        raise OACError("holder_mismatch")
    if p["sub"] != sub:
        raise OACError("subject_mismatch", "the mandate is another person's")
    if p["id"] in revoked:
        raise OACError("revoked")
    check_time(p, now, MAX_S)
    shapes.action(dict(action))
    if action["tool"] not in p["tools"] or action["tool"] != profile["tool"]:
        raise OACError("tool_not_covered")
    shapes.profile(profile)
    if tier_for(profile, policy_floor=policy_floor) == "D":
        raise OACError("tier_d")
    if tainted is not False:
        raise OACError("tainted", "outside text reached this run (or the host could not say); ask the person")
    shapes.check_action(action, profile)
    u = shapes.usage(usage)
    b, args, binds = p["bounds"], action["args"], profile.get("binds", {})
    val = lambda field: args.get(binds[field]) if field in binds else None  # noqa: E731
    if profile["effect"] == "pay":
        amt = b.get("amount", {})
        if "per_call_minor" not in amt or "per_day_minor" not in amt or "payees" not in b:
            raise OACError("pay_without_caps")
    if "to" in binds:
        to = val("to") or []
        if "recipients" not in b or not all(_recipient_ok(x, b["recipients"]) for x in to):
            raise OACError("recipient_not_allowed")
    payee = val("payee")
    if payee is not None and "payees" in b and payee not in b["payees"]:
        raise OACError("payee_not_allowed")
    site = val("site")
    if site is not None and "sites" in b and site not in b["sites"]:
        raise OACError("site_not_allowed")
    amount = val("amount_minor")
    if amount is not None:
        amt = b.get("amount")
        if amt is None:
            raise OACError("over_amount", "the mandate allows no amount")
        if val("currency") != amt["currency"]:
            raise OACError("currency_mismatch")
        if "per_call_minor" in amt and amount > amt["per_call_minor"]:
            raise OACError("over_amount")
        if "per_day_minor" in amt and u.get("amount_today_minor", 0) + amount > amt["per_day_minor"]:
            raise OACError("over_daily_amount")
    calls = b["calls"]
    if u.get("calls_today", 0) + 1 > calls["per_day"]:
        raise OACError("over_calls")
    if "per_run" in calls and u.get("calls_this_run", 0) + 1 > calls["per_run"]:
        raise OACError("over_calls")
    return p


def loosens(old: Mapping[str, Any], new: Mapping[str, Any]) -> list[str]:
    """What a replacement mandate allows that the old one did not. A signer must not sign a non-empty answer without a
    fresh proof that the person is present (spec 7.4)."""
    shapes.mandate(old)
    shapes.mandate(new)
    out: list[str] = []
    if canonical(new["holder"]) != canonical(old["holder"]):
        out.append("holder")
    if new["sub"] != old["sub"]:
        out.append("sub")
    if new["iss"] != old["iss"]:
        out.append("iss")
    if old["signer"]["kind"] == "device" and new["signer"]["kind"] != "device":
        out.append("signer")
    if set(new["tools"]) - set(old["tools"]):
        out.append("tools")
    if new["exp"] > old["exp"]:
        out.append("exp")
    ob, nb = old["bounds"], new["bounds"]
    for key in ("per_day", "per_run"):
        o, n = ob["calls"].get(key), nb["calls"].get(key)
        if o is not None and (n is None or n > o):
            out.append(f"calls.{key}")
    oa, na = ob.get("amount"), nb.get("amount")
    if na is not None and oa is None:
        out.append("amount")
    elif oa is not None:
        if na is None:
            out.append("amount")
        else:
            if na["currency"] != oa["currency"]:
                out.append("amount.currency")
            for key in ("per_call_minor", "per_day_minor"):
                o, n = oa.get(key), na.get(key)
                if o is not None and (n is None or n > o):
                    out.append(f"amount.{key}")
    # recipients: no list means nobody, so any list where there was none, or any new entry, loosens.
    # payees and sites: no list means no limit, so dropping the list, or a new entry, loosens.
    o, n = ob.get("recipients"), nb.get("recipients")
    if n is not None and (o is None or set(n) - set(o)):
        out.append("recipients")
    for key in ("payees", "sites"):
        o, n = ob.get(key), nb.get(key)
        if o is not None and (n is None or set(n) - set(o)):
            out.append(key)
    return out
