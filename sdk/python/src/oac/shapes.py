"""Field checks for every OAC object. Same rules as schemas/, plus the cross-field ones."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

from oac.errors import OACError
from oac.jcs import canonical

VERSION = "0.2"
EFFECTS = ("read", "write", "send", "pay", "delete")
UNDO_KINDS = ("native", "compensate", "none")
TIERS = ("A", "B", "C", "D")
RAILS = ("stripe_link", "ap2", "vi", "other")
HOLDERS = ("agent", "client", "run")
SIGNERS = ("custodial", "device")
AUTHORITIES = ("consent", "mandate", "tier", "undo")
OUTCOMES = ("ok", "failed", "unknown")
PREVIEW_MAX_S = 900
YEAR_S = 366 * 86400

_ID = re.compile(r"^[\x21-\x7e]{1,256}$")
_TOOL = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")
_ARG = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_DIGEST = re.compile(r"^sha-256:[A-Za-z0-9_-]{43}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_HOST = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
# one bare ASCII address, no display name or list; a recipient rule may also be "@domain"
_LOCAL = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}"
_DOMAIN = r"[A-Za-z0-9]([A-Za-z0-9.-]{0,188}[A-Za-z0-9])?"
_EMAIL = re.compile(rf"^{_LOCAL}@{_DOMAIN}$")
_ADDR = re.compile(rf"^({_LOCAL})?@{_DOMAIN}$")
# controls, bidi overrides and zero-width characters can make shown text lie
_UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
_LAST4 = re.compile(r"^[0-9]{4}$")
_OCCURRENCE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

Check = Callable[[Any], bool]


def _int(lo: int, hi: int = 2**53 - 1) -> Check:
    return lambda v: isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _str(lo: int, hi: int) -> Check:
    return lambda v: isinstance(v, str) and lo <= len(v) <= hi


def _text(lo: int, hi: int) -> Check:
    """Text a person reads: a length range and no characters that can disguise what it says."""
    return lambda v: isinstance(v, str) and lo <= len(v) <= hi and _UNSAFE.search(v) is None


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
    "title": _text(1, 200),
    "to": _list(_re(_EMAIL), 1, 50),
    "when": _text(1, 64),
    "amount_minor": _int(0),
    "currency": _re(_CURRENCY),
    "payee": _text(1, 200),
    "site": _re(_HOST),
    "count": _int(0),
}
REQUIRED_BINDS = {"pay": ("amount_minor", "currency", "payee"), "send": ("to",)}


def _undo_rule(u: Mapping[str, Any], what: str) -> None:
    if (u["kind"] == "none") != (u["window_s"] == 0) or (u["kind"] != "none" and u["window_s"] < 60):
        raise OACError("malformed", f"{what}: undo window does not fit its kind")


def profile(v: Any) -> dict[str, Any]:
    binds = lambda b: isinstance(b, dict) and all(k in PREVIEW_FIELDS and _re(_ARG)(a) for k, a in b.items())
    others = _list(_re(_ARG), 1, 64)
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
            "other_args": (False, others),
            "occurrence": (False, _re(_ARG)),
            "occurrence_scope": (False, _re(_OCCURRENCE)),
        },
        "action profile",
    )
    _undo_rule(v["undo"], "action profile")
    if v["effect"] == "read" and v["undo"]["kind"] != "none":
        raise OACError("malformed", "action profile: a read declares undo none")
    bound = list(v.get("binds", {}).values())
    if len(set(bound)) != len(bound) or set(bound) & set(v.get("other_args", [])):
        raise OACError("malformed", "action profile: an argument is declared twice")
    missing = [f for f in REQUIRED_BINDS.get(v["effect"], ()) if f not in v.get("binds", {})]
    if missing:
        raise OACError("malformed", f"action profile: a {v['effect']} tool must bind {missing[0]}")
    if v["effect"] == "pay" and "occurrence" not in v:
        raise OACError("malformed", "action profile: a pay tool names its occurrence argument")
    if "occurrence" in v and v["occurrence"] not in set(bound) | set(v.get("other_args", [])):
        raise OACError("malformed", "action profile: the occurrence argument is not declared")
    if "occurrence_scope" in v and "occurrence" not in v:
        raise OACError("malformed", "action profile: an occurrence scope needs an occurrence")
    return v


def check_action(action_doc: Mapping[str, Any], prof: Mapping[str, Any]) -> None:
    """Every argument is declared and every bound value is a valid field."""
    binds, args = prof.get("binds", {}), action_doc["args"]
    declared = set(binds.values()) | set(prof.get("other_args", []))
    extra = sorted(set(args) - declared)
    if extra:
        raise OACError("undeclared_argument", f"argument {extra[0]} is not in the tool's profile")
    for field, arg in binds.items():
        if arg in args and not PREVIEW_FIELDS[field](args[arg]):
            raise OACError("malformed", f"argument {arg} is not a valid {field}")
    for field in REQUIRED_BINDS.get(prof["effect"], ()):
        if binds[field] not in args:
            raise OACError("malformed", f"a {prof['effect']} action needs {binds[field]}")
    if "occurrence" in prof and not _re(_OCCURRENCE)(args.get(prof["occurrence"])):
        raise OACError("malformed", f"argument {prof['occurrence']} must name the occurrence")


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
            "summary": (True, _text(1, 500)),
            "fields": (True, fields),
            "details": (False, lambda d: isinstance(d, dict) and all(_re(_ARG)(k) for k in d)),
            "undo": (True, _obj(UNDO, "undo")),
            "cancel_policy": (False, _obj({"text": (True, _str(1, 2000)), "source": (False, _str(1, 2048))}, "cancel_policy")),
            "evidence": (False, lambda e: isinstance(e, dict) and len(e) > 0 and _obj({"screenshot": (False, DIGEST), "dom": (False, DIGEST)}, "evidence")(e)),
            "iat": (True, TIME),
            "exp": (True, TIME),
        },
        "preview",
    )
    _undo_rule(v["undo"], "preview")
    if not v["iat"] < v["exp"] <= v["iat"] + PREVIEW_MAX_S:
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
            "status": (False, _obj({"list": (True, ID), "index": (True, _int(0, 2 * 1024 * 1024 * 8 - 1))}, "status")),
        },
        "mandate",
    )
    return v


JWK_FIELDS = {"kty": (True, _enum("OKP", "EC")), "crv": (True, _enum("Ed25519", "P-256")), "x": (True, _str(1, 64)),
              "y": (False, _str(1, 64)), "kid": (False, _str(1, 64)), "alg": (False, _enum("EdDSA", "ES256")),
              "use": (False, _const("sig"))}


def status_list(v: Any) -> dict[str, Any]:
    check(
        v,
        {
            "oac": (True, _const(VERSION)),
            "type": (True, _const("status-list")),
            "iss": (True, ID),
            "id": (True, ID),
            "purpose": (True, _const("revocation")),
            "encoded_list": (True, _str(2, 4 * 1024 * 1024)),
            "iat": (True, TIME),
            "exp": (True, TIME),
        },
        "status list",
    )
    if not v["iat"] < v["exp"] <= v["iat"] + 7 * 86400:
        raise OACError("malformed", "status list: exp must be after iat and at most 7 days later")
    return v


def issuer_metadata(v: Any) -> dict[str, Any]:
    check(
        v,
        {
            "oac": (True, _const(VERSION)),
            "type": (True, _const("issuer-metadata")),
            "issuer": (True, ID),
            "keys": (True, _list(_obj(JWK_FIELDS, "jwk"), 1, 20)),
            "status_lists": (False, _list(ID, 1, 20)),
        },
        "issuer metadata",
    )
    return v


def seal(v: Any) -> dict[str, Any]:
    check(
        v,
        {
            "oac": (True, _const(VERSION)),
            "type": (True, _const("seal")),
            "iss": (True, ID),
            "sub": (True, ID),
            "executor": (True, ID),
            "seq": (True, _int(1)),
            "head": (True, DIGEST),
            "iat": (True, TIME),
        },
        "seal",
    )
    return v


def receipt(v: Any) -> dict[str, Any]:
    authority = {"kind": (True, _enum(*AUTHORITIES)), "ref": (False, _str(1, 256)), "digest": (False, DIGEST)}
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
            "outcome": (True, _enum(*OUTCOMES)),
            "result": (True, DIGEST),
            "undo": (True, _obj(undo, "undo")),
            "undoes": (False, DIGEST),
            "payment": (False, _obj(payment, "payment")),
            "occurrence": (False, _re(_OCCURRENCE)),
            "occurrence_scope": (False, _re(_OCCURRENCE)),
        },
        "receipt",
    )
    if "occurrence_scope" in v and "occurrence" not in v:
        raise OACError("malformed", "receipt: an occurrence scope needs an occurrence")
    return v


def usage(v: Any) -> dict[str, int]:
    """A mandate's use so far, from the executor's own counters (spec 7.3)."""
    if v is None:
        return {}
    check(v, {"calls_today": (False, _int(0)), "calls_this_run": (False, _int(0)), "amount_today_minor": (False, _int(0))}, "usage")
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


def device_proof(v: Any) -> dict[str, Any]:
    b64 = _re(re.compile(r"^[A-Za-z0-9_-]{1,8192}$"))
    check(
        v,
        {
            "oac": (True, _const(VERSION)),
            "type": (True, _const("device-proof")),
            "consent": (True, DIGEST),
            "credential": (True, _re(re.compile(r"^[A-Za-z0-9_-]{1,1366}$"))),
            "authenticator_data": (True, b64),
            "client_data_json": (True, b64),
            "signature": (True, b64),
        },
        "device proof",
    )
    return v
