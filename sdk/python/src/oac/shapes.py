"""Field-level checks for every OAC object: the same rules as schemas/*.schema.json, plus the few cross-field rules a
JSON Schema cannot say (marked "rule"). Every failure is `malformed`. Unknown fields are refused."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

from oac.errors import OACError
from oac.jcs import canonical

VERSION = "0.1"
EFFECTS = ("read", "write", "send", "pay", "delete")
UNDO_KINDS = ("native", "compensate", "none")
TIERS = ("A", "B", "C", "D")
RAILS = ("stripe_link", "ap2", "vi", "other")
HOLDERS = ("agent", "client", "run")
SIGNERS = ("custodial", "device")
AUTHORITIES = ("consent", "mandate", "tier", "undo")
PREVIEW_MAX_S = 900
YEAR_S = 366 * 86400

_ID = re.compile(r"^[\x21-\x7e]{1,256}$")
_TOOL = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")
_ARG = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_DIGEST = re.compile(r"^sha-256:[A-Za-z0-9_-]{43}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_HOST = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
_ADDR = re.compile(r"^([^@\s]{1,64}@[^@\s]{1,190}|@[^@\s]{1,190})$")
_LAST4 = re.compile(r"^[0-9]{4}$")

Check = Callable[[Any], bool]


def _int(lo: int, hi: int = 2**53 - 1) -> Check:
    return lambda v: isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _str(lo: int, hi: int) -> Check:
    return lambda v: isinstance(v, str) and lo <= len(v) <= hi


def _re(rx: re.Pattern[str]) -> Check:
    return lambda v: isinstance(v, str) and rx.fullmatch(v) is not None


def _enum(*vals: str) -> Check:
    return lambda v: isinstance(v, str) and v in vals


def _const(val: str) -> Check:
    return lambda v: v == val


def _list(item: Check, lo: int, hi: int, unique: bool = True) -> Check:
    def ok(v: Any) -> bool:
        if not isinstance(v, list) or not lo <= len(v) <= hi or not all(item(x) for x in v):
            return False
        return not unique or len({canonical(x) for x in v}) == len(v)

    return ok


def _obj(fields: Mapping[str, tuple[bool, Check]], what: str) -> Check:
    def ok(v: Any) -> bool:
        check(v, fields, what)
        return True

    return ok


def check(v: Any, fields: Mapping[str, tuple[bool, Check]], what: str) -> None:
    if not isinstance(v, dict):
        raise OACError("malformed", f"{what} must be an object")
    extra = set(v) - set(fields)
    if extra:
        raise OACError("malformed", f"{what}: unknown field {sorted(extra)[0]}")
    for name, (required, ok) in fields.items():
        if name not in v:
            if required:
                raise OACError("malformed", f"{what}: missing {name}")
            continue
        if not ok(v[name]):
            raise OACError("malformed", f"{what}: bad {name}")


ID, TOOL, DIGEST, NONCE = _re(_ID), _re(_TOOL), _re(_DIGEST), _re(_NONCE)
TIME = _int(0)
UNDO = {"kind": (True, _enum(*UNDO_KINDS)), "window_s": (True, _int(0, YEAR_S)), "note": (False, _str(1, 200))}
PREVIEW_FIELDS: dict[str, Check] = {
    "title": _str(1, 200),
    "to": _list(_str(1, 254), 1, 50),
    "when": _str(1, 64),
    "amount_minor": _int(0),
    "currency": _re(_CURRENCY),
    "payee": _str(1, 200),
    "site": _re(_HOST),
    "count": _int(0),
}


def _undo_rule(u: Mapping[str, Any], what: str) -> None:
    # rule: "none" has no window; native and compensate stay open at least a minute
    if (u["kind"] == "none") != (u["window_s"] == 0) or (u["kind"] != "none" and u["window_s"] < 60):
        raise OACError("malformed", f"{what}: undo window does not fit its kind")


def profile(v: Any) -> dict[str, Any]:
    binds = lambda b: isinstance(b, dict) and all(k in PREVIEW_FIELDS and _re(_ARG)(a) for k, a in b.items())
    check(
        v,
        {
            "oac": (True, _const(VERSION)),
            "type": (True, _const("action-profile")),
            "tool": (True, TOOL),
            "effect": (True, _enum(*EFFECTS)),
            "undo": (True, _obj(UNDO, "undo")),
            "tier_floor": (True, _enum(*TIERS)),
            "binds": (False, binds),
        },
        "action profile",
    )
    _undo_rule(v["undo"], "action profile")
    if v["effect"] == "read" and v["undo"]["kind"] != "none":  # rule: a read has nothing to undo
        raise OACError("malformed", "action profile: a read declares undo none")
    return v


def action(v: Any) -> dict[str, Any]:
    check(v, {"tool": (True, TOOL), "args": (True, lambda a: isinstance(a, dict))}, "action")
    return v


def preview(v: Any) -> dict[str, Any]:
    fields = lambda f: isinstance(f, dict) and all(k in PREVIEW_FIELDS and PREVIEW_FIELDS[k](x) for k, x in f.items())
    check(
        v,
        {
            "oac": (True, _const(VERSION)),
            "type": (True, _const("preview")),
            "id": (True, ID),
            "executor": (True, ID),
            "sub": (True, ID),
            "tool": (True, TOOL),
            "action": (True, DIGEST),
            "summary": (True, _str(1, 500)),
            "fields": (True, fields),
            "undo": (True, _obj(UNDO, "undo")),
            "cancel_policy": (False, _obj({"text": (True, _str(1, 2000)), "source": (False, _str(1, 2048))}, "cancel_policy")),
            "evidence": (False, lambda e: isinstance(e, dict) and len(e) > 0 and _obj({"screenshot": (False, DIGEST), "dom": (False, DIGEST)}, "evidence")(e)),
            "iat": (True, TIME),
            "exp": (True, TIME),
        },
        "preview",
    )
    _undo_rule(v["undo"], "preview")
    if not v["iat"] < v["exp"] <= v["iat"] + PREVIEW_MAX_S:  # rule
        raise OACError("malformed", "preview: exp must be after iat and at most 15 minutes later")
    return v


PAYMENT = {
    "rail": (True, _enum(*RAILS)),
    "ref": (True, _str(1, 256)),
    "amount_minor": (True, _int(0)),
    "currency": (True, _re(_CURRENCY)),
    "payee": (True, _str(1, 200)),
}


def consent(v: Any) -> dict[str, Any]:
    item = _obj({"preview": (True, DIGEST), "action": (True, DIGEST)}, "item")
    check(
        v,
        {
            "oac": (True, _const(VERSION)),
            "type": (True, _const("consent")),
            "iss": (True, ID),
            "sub": (True, ID),
            "aud": (True, ID),
            "jti": (True, NONCE),
            "iat": (True, TIME),
            "exp": (True, TIME),
            "items": (True, _list(item, 1, 20)),
            "signer": (True, _obj({"kind": (True, _enum(*SIGNERS))}, "signer")),
            "payment": (False, _obj(PAYMENT, "payment")),
        },
        "consent",
    )
    return v


def mandate(v: Any) -> dict[str, Any]:
    calls = {"per_day": (True, _int(1, 10000)), "per_run": (False, _int(1, 1000))}
    amount = {"currency": (True, _re(_CURRENCY)), "per_call_minor": (False, _int(0)), "per_day_minor": (False, _int(0))}
    bounds = {
        "calls": (True, _obj(calls, "calls")),
        "amount": (False, lambda a: _obj(amount, "amount")(a) and len(a) >= 2),
        "recipients": (False, _list(_re(_ADDR), 1, 100)),
        "payees": (False, _list(_str(1, 200), 1, 100)),
        "sites": (False, _list(_re(_HOST), 1, 100)),
    }
    check(
        v,
        {
            "oac": (True, _const(VERSION)),
            "type": (True, _const("mandate")),
            "id": (True, ID),
            "iss": (True, ID),
            "sub": (True, ID),
            "holder": (True, _obj({"type": (True, _enum(*HOLDERS)), "id": (True, ID)}, "holder")),
            "goal": (True, _str(1, 300)),
            "tools": (True, _list(TOOL, 1, 32)),
            "bounds": (True, _obj(bounds, "bounds")),
            "iat": (True, TIME),
            "exp": (True, TIME),
            "signer": (True, _obj({"kind": (True, _enum(*SIGNERS))}, "signer")),
            "supersedes": (False, ID),
        },
        "mandate",
    )
    return v


def receipt(v: Any) -> dict[str, Any]:
    authority = {"kind": (True, _enum(*AUTHORITIES)), "ref": (False, _str(1, 256))}
    undo = {"kind": (True, _enum(*UNDO_KINDS)), "until": (False, TIME), "token": (False, _str(1, 512))}
    payment = {"rail": (True, _enum(*RAILS)), "ref": (True, _str(1, 256)), "last4": (False, _re(_LAST4)), "order": (False, _str(1, 256))}
    check(
        v,
        {
            "oac": (True, _const(VERSION)),
            "type": (True, _const("receipt")),
            "iss": (True, ID),
            "sub": (True, ID),
            "seq": (True, _int(1)),
            "prev": (True, lambda p: p is None or DIGEST(p)),
            "iat": (True, TIME),
            "tool": (True, TOOL),
            "tier": (True, _enum(*TIERS)),
            "authority": (True, _obj(authority, "authority")),
            "action": (True, DIGEST),
            "preview": (False, DIGEST),
            "outcome": (True, _enum("ok", "failed")),
            "result": (True, DIGEST),
            "undo": (True, _obj(undo, "undo")),
            "undoes": (False, DIGEST),
            "payment": (False, _obj(payment, "payment")),
        },
        "receipt",
    )
    return v


def undo_request(v: Any) -> dict[str, Any]:
    check(
        v,
        {
            "oac": (True, _const(VERSION)),
            "type": (True, _const("undo")),
            "iss": (True, ID),
            "sub": (True, ID),
            "aud": (True, ID),
            "jti": (True, NONCE),
            "iat": (True, TIME),
            "exp": (True, TIME),
            "receipt": (True, DIGEST),
            "mode": (True, _enum("native", "compensate")),
            "consent": (False, NONCE),
        },
        "undo request",
    )
    return v
