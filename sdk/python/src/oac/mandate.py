"""Mandates (spec section 7): a standing, bounded, expiring permission. It can stand in for a Consent on tier C only;
it never covers tier D, never waives the taint floor, and a pay tool needs caps and a payee list."""

from __future__ import annotations

from collections.abc import Mapping
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
    a = addr.lower()
    for rule in allowed:
        r = rule.lower()
        if (r.startswith("@") and a.endswith(r)) or a == r:
            return True
    return False


def check_mandate(
    token: str,
    *,
    keys: KeySet,
    action: Mapping[str, Any],
    profile: Mapping[str, Any],
    holder: Mapping[str, Any],
    now: int,
    usage: Mapping[str, int] | None = None,
    tainted: bool = False,
    policy_floor: str = "A",
) -> dict[str, Any]:
    """`usage` = what this mandate already did: calls_today, calls_this_run, amount_today_minor."""
    p = verify(token, keys, TYP)
    shapes.mandate(p)
    if canonical(p["holder"]) != canonical(holder):
        raise OACError("holder_mismatch")
    check_time(p, now, MAX_S)
    shapes.action(dict(action))
    if action["tool"] not in p["tools"] or action["tool"] != profile["tool"]:
        raise OACError("tool_not_covered")
    if tier_for(profile, policy_floor=policy_floor) == "D":
        raise OACError("tier_d")
    if tainted:
        raise OACError("tainted", "outside text reached this run; ask the person")
    b, args, binds = p["bounds"], action["args"], profile.get("binds", {})
    for field, arg in binds.items():
        if arg in args and not shapes.PREVIEW_FIELDS[field](args[arg]):
            raise OACError("malformed", f"argument {arg} is not a valid {field}")
    val = lambda field: args.get(binds[field]) if field in binds else None  # noqa: E731
    if profile["effect"] == "pay":
        amt = b.get("amount", {})
        if "per_call_minor" not in amt or "per_day_minor" not in amt or "payees" not in b:
            raise OACError("pay_without_caps")
    to = val("to")
    if to is not None:
        if "recipients" not in b or not all(_recipient_ok(x, b["recipients"]) for x in to):
            raise OACError("recipient_not_allowed")
    payee = val("payee")
    if payee is not None and "payees" in b and payee not in b["payees"]:
        raise OACError("payee_not_allowed")
    site = val("site")
    if site is not None and "sites" in b and site not in b["sites"]:
        raise OACError("site_not_allowed")
    u = usage or {}
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
    out: list[str] = []
    if canonical(new["holder"]) != canonical(old["holder"]):
        out.append("holder")
    if new["sub"] != old["sub"]:
        out.append("sub")
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
    for key in ("recipients", "payees", "sites"):
        o, n = ob.get(key), nb.get(key)
        if o is not None and (n is None or set(n) - set(o)):
            out.append(key)
    return out
