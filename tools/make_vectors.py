"""Write vectors/*.json. Expected results are written by hand from the spec; the SDK must agree.

Run from the repo root: python tools/make_vectors.py"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

from oac import shapes  # noqa: E402
from oac.conformance import run_case  # noqa: E402
from oac.consent import make_consent  # noqa: E402
from oac.jcs import canonical_bytes  # noqa: E402
from oac.jws import _signature, b64url, digest, sign, token_digest  # noqa: E402
from oac.mandate import make_mandate  # noqa: E402
from oac.preview import action_digest, build_preview  # noqa: E402
from oac.receipts import make_receipt  # noqa: E402
from oac.testing import vector_key  # noqa: E402
from oac.undo import make_undo  # noqa: E402
from oac.receipts import make_seal  # noqa: E402
from oac.status import encode, make_status_list  # noqa: E402
from oac.testing import passkey_proof  # noqa: E402
from oac.webauthn import USER_PRESENT, USER_VERIFIED  # noqa: E402

NOW = 1793836800  # 2026-11-05T00:00:00Z
EXECUTOR = "https://shop.example/oac"
SIGNER = "https://atlas.example/signer"
PERSON = "person:7f3a"
USER = vector_key("signer")
DEVICE = vector_key("device", "ES256")
PASSKEY = vector_key("passkey", "ES256")
EXEC = vector_key("executor")
ATTACKER = vector_key("attacker")
WALLET = vector_key("wallet")  # a second signer the executor also trusts
OTHER_EXEC = vector_key("other-executor")
WALLET_ISS = "https://wallet.example"
OTHER_EXECUTOR = "https://other.example/oac"
USER_KEYS = {SIGNER: [USER.jwk, DEVICE.jwk], WALLET_ISS: [WALLET.jwk]}
EXEC_KEYS = {EXECUTOR: [EXEC.jwk], OTHER_EXECUTOR: [OTHER_EXEC.jwk]}
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
CONSENT_TYP, MANDATE_TYP, RECEIPT_TYP = "oac-consent+jws", "oac-mandate+jws", "oac-receipt+jws"


def profile(tool: str, effect: str, kind: str, window: int, binds: dict[str, str], floor: str = "A",
            others: list[str] | None = None, occurrence: str | None = None) -> dict[str, Any]:
    doc = {
        "oac": "0.1",
        "type": "action-profile",
        "tool": tool,
        "effect": effect,
        "undo": {"kind": kind, "window_s": window},
        "tier_floor": floor,
        "binds": binds,
    }
    if others:
        doc["other_args"] = others
    if occurrence:
        doc["occurrence"] = occurrence
    return doc


PROFILES = {
    "book_table": profile("book_table", "write", "compensate", 86400, {"payee": "restaurant", "when": "time", "count": "party", "site": "site"}),
    "send_email": profile("send_email", "send", "none", 0, {"to": "to", "title": "subject"}, others=["body"]),
    "add_task": profile("add_task", "write", "native", 600, {"title": "title"}),
    "pay_order": profile("pay_order", "pay", "compensate", 604800, {"amount_minor": "amount_minor", "currency": "currency", "payee": "merchant"},
                         others=["items", "order"], occurrence="order"),
    "read_calendar": profile("read_calendar", "read", "none", 0, {}),
    "solve_captcha": profile("solve_captcha", "write", "none", 0, {}, floor="D", others=["page"]),
    "cancel_booking": profile("cancel_booking", "write", "none", 0, {"payee": "restaurant"}, others=["undoes"]),
}

ACTIONS = {
    "book": {"tool": "book_table", "args": {"restaurant": "Nobu Boston", "time": "2026-11-06T19:30-05:00", "party": 2, "site": "nobu.example"}},
    "pay": {"tool": "pay_order", "args": {"amount_minor": 1800, "currency": "USD", "merchant": "Sweetgreen", "items": ["bowl"],
                                          "order": "ord_2231"}},
    "captcha": {"tool": "solve_captcha", "args": {"page": "https://x.example"}},
}


def mail(n: int) -> dict[str, Any]:
    return {"tool": "send_email", "args": {"to": [f"sam{n}@example.com"], "subject": f"Re: plan {n}", "body": "Sounds good."}}


def pv(action: dict[str, Any], summary: str, *, now: int = NOW - 30, **kw: Any) -> dict[str, Any]:
    return build_preview(
        profile=PROFILES[action["tool"]], action=action, executor=kw.pop("executor", EXECUTOR), sub=kw.pop("sub", PERSON),
        summary=summary, now=now, preview_id=kw.pop("preview_id", "pv_" + action["tool"]), **kw,
    )


def consent(previews: list[dict[str, Any]], *, key: Any = USER, **kw: Any) -> str:
    return make_consent(
        key=key, iss=SIGNER, sub=kw.pop("sub", PERSON), aud=kw.pop("aud", EXECUTOR), previews=previews,
        now=kw.pop("now", NOW - 20), jti=kw.pop("jti", "n_consent_0000000001"), **kw,
    )


def raw_token(header: dict[str, Any] | bytes, payload: bytes, key: Any) -> str:
    """A token built by hand, for defects make_* would refuse to produce. Signed correctly over what it carries."""
    h = header if isinstance(header, bytes) else canonical_bytes(header)
    signing_input = b64url(h) + "." + b64url(payload)
    return signing_input + "." + b64url(_signature(key, signing_input.encode("ascii")))


def payload_of(token: str) -> dict[str, Any]:
    import base64

    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def resign(token: str, change: dict[str, Any], key: Any = USER, typ: str = CONSENT_TYP) -> str:
    return sign({**payload_of(token), **change}, key, typ)


def consent_input(token: str, previews: list[dict[str, Any]], actions: list[dict[str, Any]], **kw: Any) -> dict[str, Any]:
    return {"token": token, "keys": USER_KEYS, "executor": EXECUTOR, "sub": PERSON, "previews": previews,
            "actions": actions, "profiles": PROFILES, "now": NOW, **kw}


def high_s(token: str) -> str:
    """The other valid-looking spelling of an ES256 signature (s -> n - s)."""
    import base64

    head, body, sig = token.split(".")
    raw = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
    s_val = int.from_bytes(raw[32:], "big")
    return f"{head}.{body}.{b64url(raw[:32] + (P256_N - s_val).to_bytes(32, 'big'))}"


def manual_preview(base: dict[str, Any], action: dict[str, Any], **change: Any) -> dict[str, Any]:
    """A preview a lying or buggy executor built by hand (build_preview would refuse it)."""
    return copy.deepcopy(base) | {"action": action_digest(action)} | change


def ok() -> dict[str, Any]:
    return {"ok": True}


def err(code: str) -> dict[str, Any]:
    return {"error": code}


# canonical JSON, digests, signing, tiers
def basics() -> list[dict[str, Any]]:
    c: list[dict[str, Any]] = []
    jcs = [
        ("sorts keys", {"b": 1, "a": [3, {"d": None, "c": True}]}, '{"a":[3,{"c":true,"d":null}],"b":1}'),
        ("sorts by UTF-16 code units, not code points", {"דּ": 1, "\U0001f600": 2, "€": 3}, '{"€":3,"\U0001f600":2,"דּ":1}'),
        ("escapes like JSON.stringify", {"s": "\u0001\n\"\\/é"}, '{"s":"\\u0001\\n\\"\\\\/é"}'),
        ("negative and large safe integers", {"n": [-1, 0, 9007199254740991]}, '{"n":[-1,0,9007199254740991]}'),
        ("empty containers", {"o": {}, "a": []}, '{"a":[],"o":{}}'),
    ]
    for name, value, want in jcs:
        c.append({"name": name, "op": "jcs", "input": {"value": value}, "expect": {"canonical": want}})
    parses = [
        ("duplicate key is refused", '{"a":1,"a":2}', err("malformed")),
        ("fraction is refused", '{"amount":1.5}', err("malformed")),
        ("1.0 is refused (no non-integer spelling)", '{"amount":1.0}', err("malformed")),
        ("exponent is refused", '{"amount":1e2}', err("malformed")),
        ("NaN is refused", '{"amount":NaN}', err("malformed")),
        ("trailing garbage is refused", '{"a":1} x', err("malformed")),
        ("whitespace is fine when parsing", '{ "b" : 2 , "a" : [ 1 ] }', {"canonical": '{"a":[1],"b":2}'}),
        ("integer beyond 2^53-1 is refused", '{"n":9007199254740992}', err("malformed")),
        ("64 levels of nesting are fine", "[" * 64 + "]" * 64, {"canonical": "[" * 64 + "]" * 64}),
        ("65 levels of nesting are refused", "[" * 65 + "]" * 65, err("malformed")),
        ("a key that is a lone surrogate is refused", '{"\\ud800":1}', err("malformed")),
        ("a byte-order mark is refused", "\ufeff{}", err("malformed")),
    ]
    for name, text, want in parses:
        c.append({"name": name, "op": "parse", "input": {"text": text}, "expect": want})
    value = {"tool": "book_table", "args": {"party": 2, "restaurant": "Nobu Boston"}}
    c.append({"name": "digest is sha-256 over JCS bytes", "op": "digest", "input": {"value": value}, "expect": {"digest": digest(value)}})
    payload = {"oac": "0.1", "type": "consent", "note": "deterministic EdDSA"}
    c.append({"name": "EdDSA signing is deterministic across SDKs", "op": "sign",
              "input": {"key": "signer", "typ": CONSENT_TYP, "payload": payload}, "expect": {"token": sign(payload, USER, CONSENT_TYP)}})
    tiers = [
        ("a read is A", "read_calendar", {}, "A"),
        ("a native-undo write is B", "add_task", {}, "B"),
        ("a compensate write is C", "book_table", {}, "C"),
        ("a send is C", "send_email", {}, "C"),
        ("a pay is C", "pay_order", {}, "C"),
        ("a D floor is D", "solve_captcha", {}, "D"),
        ("a model hint cannot lower C to A", "book_table", {"hint": "A"}, "C"),
        ("a hint can raise B to C", "add_task", {"hint": "C"}, "C"),
        ("taint raises a write to C", "add_task", {"tainted": True}, "C"),
        ("taint leaves a read at A", "read_calendar", {"tainted": True}, "A"),
        ("policy floor raises a read to B", "read_calendar", {"policy_floor": "B"}, "B"),
    ]
    for name, tool, extra, want in tiers:
        c.append({"name": name, "op": "tier", "input": {"profile": PROFILES[tool], **extra}, "expect": {"tier": want}})
    for bad in ["CD", "", "c"]:
        c.append({"name": f"tier name {bad!r} is refused", "op": "tier", "input": {"profile": PROFILES["read_calendar"], "hint": bad}, "expect": err("malformed")})
    bad_profiles = [
        ("a read that claims an undo", {**PROFILES["read_calendar"], "undo": {"kind": "native", "window_s": 600}}),
        ("undo none with a window", {**PROFILES["send_email"], "undo": {"kind": "none", "window_s": 600}}),
        ("native undo shorter than a minute", {**PROFILES["add_task"], "undo": {"kind": "native", "window_s": 30}}),
        ("unknown effect", {**PROFILES["add_task"], "effect": "teleport"}),
        ("bind to an unknown preview field", {**PROFILES["add_task"], "binds": {"colour": "title"}}),
        ("unknown top-level field", {**PROFILES["add_task"], "trust_me": True}),
        ("a field named like a JavaScript built-in", {**PROFILES["add_task"], "constructor": 1}),
        ("a pay tool that does not bind the amount", {**PROFILES["pay_order"], "binds": {"currency": "currency", "payee": "merchant"}}),
        ("a send tool that does not bind recipients", {**PROFILES["send_email"], "binds": {"title": "subject"}}),
        ("an argument both bound and listed as other", {**PROFILES["send_email"], "other_args": ["body", "to"]}),
        ("a pay tool that names no occurrence", {k: v for k, v in PROFILES["pay_order"].items() if k != "occurrence"}),
        ("an occurrence argument the tool does not declare", {**PROFILES["pay_order"], "occurrence": "cart"}),
    ]
    c.append({"name": "a valid profile", "op": "profile", "input": {"profile": PROFILES["book_table"]}, "expect": ok()})
    for name, p in bad_profiles:
        c.append({"name": name, "op": "profile", "input": {"profile": p}, "expect": err("malformed")})
    return c


# consent
def consents() -> list[dict[str, Any]]:
    c: list[dict[str, Any]] = []
    book, pay = ACTIONS["book"], ACTIONS["pay"]
    p_book = pv(book, "Book Nobu Boston, Fri 6 Nov 7:30 pm, 2 people. Free cancel until 24 h before.")
    good = consent([p_book])
    base = consent_input(good, [p_book], [book])

    def case(name: str, expect: dict[str, Any], **change: Any) -> None:
        c.append({"name": name, "op": "verify_consent", "input": {**base, **change}, "expect": expect})

    case("valid: one preview, one action", ok())
    mails = [mail(i) for i in range(3)]
    p_mails = [pv(m, f"Email sam{i}@example.com: Re: plan {i}", preview_id=f"pv_mail_{i}") for i, m in enumerate(mails)]
    case("valid: one yes for a batch of three emails", ok(), token=consent(p_mails, jti="n_consent_0000000002"), previews=p_mails, actions=mails)
    p_pay = pv(pay, "Pay Sweetgreen $18.00 for 1 bowl. Refund within 7 days.")
    pay_ref = {"rail": "stripe_link", "ref": "lsrq_test_123", "amount_minor": 1800, "currency": "USD", "payee": "Sweetgreen"}
    case("valid: payment matches the preview", ok(), token=consent([p_pay], payment=pay_ref, jti="n_consent_0000000003"), previews=[p_pay], actions=[pay])
    case("valid: ES256 device key", ok(), token=consent([p_book], key=DEVICE, signer_kind="device", jti="n_consent_0000000004"))
    case("valid: tainted run still runs with a consent", ok(), tainted=True)

    # envelope
    forged = good.split(".")
    attacker_sig = raw_token({"alg": "EdDSA", "kid": USER.kid, "typ": CONSENT_TYP}, canonical_bytes(payload_of(good)), ATTACKER)
    case("forged: attacker signs with the person's kid", err("bad_signature"), token=attacker_sig)
    case("unknown key", err("unknown_key"), token=consent([p_book], key=ATTACKER))
    case("wrong type: a receipt-typed token", err("bad_type"), token=sign(payload_of(good), USER, RECEIPT_TYP))
    case("alg none", err("bad_alg"), token=b64url(canonical_bytes({"alg": "none", "kid": USER.kid, "typ": CONSENT_TYP})) + "." + forged[1] + ".")
    spaced = json.dumps(payload_of(good), indent=1).encode()
    case("payload not canonical (signed over spaced JSON)", err("not_canonical"),
         token=raw_token({"alg": "EdDSA", "kid": USER.kid, "typ": CONSENT_TYP}, spaced, USER))
    tampered = payload_of(good) | {"exp": NOW + 800}
    case("tampered after signing", err("bad_signature"), token=forged[0] + "." + b64url(canonical_bytes(tampered)) + "." + forged[2])
    case("extra header field", err("malformed"),
         token=raw_token({"alg": "EdDSA", "kid": USER.kid, "typ": CONSENT_TYP, "crit": ["x"]}, canonical_bytes(payload_of(good)), USER))
    case("non-integer number in payload", err("malformed"),
         token=raw_token({"alg": "EdDSA", "kid": USER.kid, "typ": CONSENT_TYP}, canonical_bytes(payload_of(good))[:-1] + b',"z":1.5}', USER))
    case("duplicate key in payload", err("malformed"),
         token=raw_token({"alg": "EdDSA", "kid": USER.kid, "typ": CONSENT_TYP}, canonical_bytes(payload_of(good))[:-1] + b',"aud":"x"}', USER))
    case("not three parts", err("malformed"), token=forged[0] + "." + forged[1])

    # audience and time
    case("wrong audience", err("wrong_audience"), token=resign(good, {"aud": "https://other.example/oac"}))
    case("expired", err("expired"), now=NOW + 400)
    case("not yet valid (iat 2 min ahead)", err("not_yet_valid"), token=resign(good, {"iat": NOW + 120, "exp": NOW + 400}))
    case("lives longer than 15 minutes", err("lifetime_too_long"), token=resign(good, {"exp": NOW - 20 + 3600}))

    # binding to what the person saw
    shown = copy.deepcopy(p_book) | {"summary": "Book Nobu Boston, 2 people."}
    case("preview differs from the one signed", err("preview_mismatch"), previews=[shown])
    changed = copy.deepcopy(book)
    changed["args"]["party"] = 20
    case("action changed after the yes", err("action_mismatch"), actions=[changed])
    lying = copy.deepcopy(p_book)
    lying["action"] = action_digest(changed)  # the preview shows 2 people, the real call books 20
    case("preview fields do not match the arguments", err("binding_mismatch"), token=consent([lying], jti="n_consent_0000000005"), previews=[lying], actions=[changed])
    other_sub = pv(book, "Book Nobu Boston", sub="person:other")
    case("preview made for another person", err("subject_mismatch"), token=consent([other_sub], jti="n_consent_0000000006"), previews=[other_sub])
    other_exec = pv(book, "Book Nobu Boston", executor="https://other.example/oac")
    case("preview made by another executor", err("executor_mismatch"), token=consent([other_exec], jti="n_consent_0000000007"), previews=[other_exec])
    stale = pv(book, "Book Nobu Boston", now=NOW - 700)
    case("preview expired before the call", err("preview_expired"), token=consent([stale], jti="n_consent_0000000008"), previews=[stale])
    case("one item but two previews", err("preview_mismatch"), previews=[p_book, p_mails[0]], actions=[book, mails[0]])
    no_profiles = {k: v for k, v in PROFILES.items() if k != "book_table"}
    case("no profile for the tool", err("unknown_tool"), profiles=no_profiles)
    cap = ACTIONS["captcha"]
    p_cap = pv(cap, "Solve the CAPTCHA")
    case("tier D never runs, even with a yes", err("tier_d"), token=consent([p_cap], jti="n_consent_0000000009"), previews=[p_cap], actions=[cap])
    case("pay without a payment reference", err("payment_missing"), token=consent([p_pay], jti="n_consent_0000000010"), previews=[p_pay], actions=[pay])
    case("payment amount differs from the preview", err("payment_mismatch"),
         token=consent([p_pay], payment=pay_ref | {"amount_minor": 18000}, jti="n_consent_0000000011"), previews=[p_pay], actions=[pay])
    case("replayed nonce", err("replay"), seen_nonces=["n_consent_0000000001"])

    case("valid: a second trusted signer signs as itself", ok(), token=make_consent(
        key=WALLET, iss=WALLET_ISS, sub=PERSON, aud=EXECUTOR, previews=[p_book], now=NOW - 20, jti="n_consent_0000000012"))
    case("a trusted signer's key signs in another signer's name", err("wrong_issuer"), token=make_consent(
        key=WALLET, iss=SIGNER, sub=PERSON, aud=EXECUTOR, previews=[p_book], now=NOW - 20, jti="n_consent_0000000013"))
    case("the executor acts for someone else", err("subject_mismatch"), sub="person:other")
    device = consent([p_book], key=DEVICE, signer_kind="device", jti="n_consent_0000000014")
    case("ES256 high-S twin of a valid signature", err("bad_signature"), token=high_s(device))
    m1 = mail(1)
    p_m1 = pv(m1, "Email sam1@example.com: Re: plan 1")
    sneaky = {"tool": "send_email", "args": m1["args"] | {"bcc": ["boss@evil.test"]}}
    p_sneaky = manual_preview(p_m1, sneaky)
    case("model adds an argument the profile does not declare (bcc)", err("undeclared_argument"),
         token=consent([p_sneaky], jti="n_consent_0000000015"), previews=[p_sneaky], actions=[sneaky])
    rewritten = {"tool": "send_email", "args": m1["args"] | {"body": "Please wire $500 to the account below."}}
    p_hidden = manual_preview(p_m1, rewritten)  # still shows "Sounds good." in details
    case("details shown differ from the arguments that run", err("binding_mismatch"),
         token=consent([p_hidden], jti="n_consent_0000000016"), previews=[p_hidden], actions=[rewritten])
    listed = {"tool": "send_email", "args": m1["args"] | {"to": ["sam1@example.com, boss@evil.test"]}}
    p_listed = manual_preview(p_m1, listed, fields={"to": ["sam1@example.com, boss@evil.test"], "title": "Re: plan 1"})
    case("two addresses hidden in one recipient", err("malformed"), token=consent([p_listed], jti="n_consent_0000000017"),
         previews=[p_listed], actions=[listed])
    p_bidi = manual_preview(p_book, book, fields=p_book["fields"] | {"payee": "Nobu \u202eBoston"})
    case("a direction-override character in a shown field", err("malformed"), token=consent([p_bidi], jti="n_consent_0000000018"), previews=[p_bidi])
    bad_profiles = PROFILES | {"send_email": {k: v for k, v in PROFILES["send_email"].items()} | {"binds": {"title": "subject"}}}
    case("the tool's profile is invalid (send without recipients bound)", err("malformed"),
         token=consent([p_m1], jti="n_consent_0000000019"), previews=[p_m1], actions=[m1], profiles=bad_profiles)
    case("payment given but nothing pays", err("payment_mismatch"), token=consent([p_book], payment=pay_ref, jti="n_consent_0000000020"))
    pay2 = {"tool": "pay_order", "args": pay["args"] | {"items": ["salad"]}}
    p_pay2 = pv(pay2, "Pay Sweetgreen $18.00 for 1 salad.", preview_id="pv_pay_2")
    case("two paying items in one yes", err("malformed"), token=consent([p_pay, p_pay2], payment=pay_ref, jti="n_consent_0000000021"),
         previews=[p_pay, p_pay2], actions=[pay, pay2])
    no_order = {"tool": "pay_order", "args": pay["args"] | {"order": "ord 2231; DROP"}}
    p_no_order = manual_preview(p_pay, no_order, details={"items": ["bowl"], "order": "ord 2231; DROP"})
    case("a payment whose occurrence id is not an id", err("malformed"),
         token=consent([p_no_order], payment=pay_ref, jti="n_consent_0000000022"), previews=[p_no_order], actions=[no_order])

    # device proofs: a passkey assertion over the exact consent token (spec 3.6)
    signed = consent([p_book], jti="n_consent_0000000030")
    creds = {"cred-1": PASSKEY.jwk}

    def device(name: str, expect: dict[str, Any], proof: dict[str, Any] | None, token: str = signed, **change: Any) -> None:
        check = {"proof": proof, "credentials": creds, "rp_id": "app.example", "origins": ["https://app.example"]}
        case(name, expect, token=token, device=check, **change)

    device("valid: passkey proof over the exact consent", ok(), passkey_proof(signed, PASSKEY))
    device("passkey required but no proof given", err("device_proof_missing"), None)
    device("a proof made for another consent", err("device_proof_mismatch"),
           passkey_proof(consent([p_book], jti="n_consent_0000000031"), PASSKEY))
    device("an unregistered credential", err("unknown_credential"), passkey_proof(signed, PASSKEY, credential="cred-9"))
    device("a proof signed by another key", err("bad_signature"), passkey_proof(signed, DEVICE))
    changed = {"tool": "book_table", "args": book["args"] | {"party": 6}}
    device("valid proof, but the arguments changed after approval", err("action_mismatch"),
           passkey_proof(signed, PASSKEY), actions=[changed])
    device("the passkey signed a challenge for another token", err("challenge_mismatch"),
           passkey_proof(signed, PASSKEY, challenge_for=consent([p_book], jti="n_consent_0000000032")))
    device("assertion made on another origin", err("wrong_origin"), passkey_proof(signed, PASSKEY, origin="https://evil.example"))
    device("assertion for another relying party", err("rp_mismatch"), passkey_proof(signed, PASSKEY, rp_id="evil.example"))
    device("user not present", err("user_not_present"), passkey_proof(signed, PASSKEY, flags=USER_VERIFIED))
    device("user present but not verified (no PIN or biometric)", err("user_not_verified"),
           passkey_proof(signed, PASSKEY, flags=USER_PRESENT))
    device("a registration, not an assertion", err("malformed"), passkey_proof(signed, PASSKEY, type_="webauthn.create"))
    return c


# mandates
def mandates() -> list[dict[str, Any]]:
    c: list[dict[str, Any]] = []
    holder = {"type": "agent", "id": "lunch-bot"}
    body = {
        "id": "md_lunch_1", "iss": SIGNER, "sub": PERSON, "holder": holder,
        "goal": "Book and pay for lunch on weekdays, up to $25.",
        "tools": ["book_table", "pay_order", "send_email", "solve_captcha"],
        "bounds": {"calls": {"per_day": 5}, "amount": {"currency": "USD", "per_call_minor": 2500, "per_day_minor": 5000},
                   "payees": ["Nobu Boston", "Sweetgreen"], "recipients": ["@example.com"], "sites": ["nobu.example"]},
        "iat": NOW - 3600, "exp": NOW - 3600 + 7 * 86400, "signer": {"kind": "custodial"},
    }
    good = make_mandate(key=USER, payload=body)
    book, pay = ACTIONS["book"], ACTIONS["pay"]
    base = {"token": good, "keys": USER_KEYS, "action": book, "profile": PROFILES["book_table"], "holder": holder, "sub": PERSON,
            "now": NOW, "tainted": False}

    def case(name: str, expect: dict[str, Any], **change: Any) -> None:
        c.append({"name": name, "op": "check_mandate", "input": {**base, **change}, "expect": expect})

    def variant(**bounds: Any) -> str:
        return make_mandate(key=USER, payload=body | {"bounds": body["bounds"] | bounds})

    def with_args(action: dict[str, Any], **args: Any) -> dict[str, Any]:
        return {"tool": action["tool"], "args": action["args"] | args}

    case("valid: booking inside the bounds", ok())
    case("valid: payment inside the bounds", ok(), action=pay, profile=PROFILES["pay_order"])
    case("valid: email to an allowed domain", ok(), action=mail(1), profile=PROFILES["send_email"])
    case("another agent holds it", err("holder_mismatch"), holder={"type": "agent", "id": "other-bot"})
    case("expired", err("expired"), now=NOW + 8 * 86400)
    case("lives longer than 30 days", err("lifetime_too_long"), token=make_mandate(key=USER, payload=body | {"exp": body["iat"] + 31 * 86400}))
    case("tool not in the mandate", err("tool_not_covered"), action={"tool": "add_task", "args": {"title": "x"}}, profile=PROFILES["add_task"])
    case("tier D tool, even when listed", err("tier_d"), action=ACTIONS["captcha"], profile=PROFILES["solve_captcha"])
    case("tainted run: a mandate never waives the ask", err("tainted"), tainted=True)
    no_caps = make_mandate(key=USER, payload=body | {"bounds": {"calls": {"per_day": 5}, "payees": ["Sweetgreen"],
                                                                 "amount": {"currency": "USD", "per_call_minor": 2500}}})
    case("pay mandate without a daily cap", err("pay_without_caps"), token=no_caps, action=pay, profile=PROFILES["pay_order"])
    case("recipient outside the list", err("recipient_not_allowed"), action=with_args(mail(1), to=["boss@evil.test"]), profile=PROFILES["send_email"])
    no_recipients = make_mandate(key=USER, payload=body | {"bounds": {k: v for k, v in body["bounds"].items() if k != "recipients"}})
    case("sending to people needs a recipient list", err("recipient_not_allowed"), token=no_recipients, action=mail(1), profile=PROFILES["send_email"])
    case("payee outside the list", err("payee_not_allowed"), action=with_args(pay, merchant="Gadget Store"), profile=PROFILES["pay_order"])
    case("site outside the list", err("site_not_allowed"), action=with_args(book, site="evil.example"))
    case("currency differs", err("currency_mismatch"), action=with_args(pay, currency="EUR"), profile=PROFILES["pay_order"])
    case("over the per-call amount", err("over_amount"), action=with_args(pay, amount_minor=3000), profile=PROFILES["pay_order"])
    case("over the daily amount", err("over_daily_amount"), action=pay, profile=PROFILES["pay_order"], usage={"amount_today_minor": 4000})
    case("over the daily call count", err("over_calls"), usage={"calls_today": 5})
    case("over the per-run call count", err("over_calls"), token=variant(calls={"per_day": 5, "per_run": 1}), usage={"calls_this_run": 1})
    case("forged signature", err("bad_signature"),
         token=raw_token({"alg": "EdDSA", "kid": USER.kid, "typ": MANDATE_TYP}, canonical_bytes(payload_of(good)), ATTACKER))
    case("a consent-typed token", err("bad_type"), token=sign(payload_of(good), USER, CONSENT_TYP))

    # loosening: a signer must ask for fresh proof before signing any non-empty answer
    old = {"oac": "0.1", "type": "mandate", **body}

    def loose(name: str, new: dict[str, Any], reasons: list[str]) -> None:
        c.append({"name": name, "op": "loosens", "input": {"old": old, "new": new}, "expect": {"reasons": sorted(reasons)}})

    nb = old["bounds"]
    loose("narrowing is not loosening", old | {"tools": ["book_table"], "bounds": nb | {"calls": {"per_day": 2}}}, [])
    loose("a new tool", old | {"tools": old["tools"] + ["add_task"]}, ["tools"])
    loose("a higher per-call amount", old | {"bounds": nb | {"amount": nb["amount"] | {"per_call_minor": 9900}}}, ["amount.per_call_minor"])
    loose("a new recipient", old | {"bounds": nb | {"recipients": ["@example.com", "@gmail.com"]}}, ["recipients"])
    loose("a later expiry", old | {"exp": old["exp"] + 86400}, ["exp"])
    loose("dropping the payee list", old | {"bounds": {k: v for k, v in nb.items() if k != "payees"}}, ["payees"])
    loose("another holder and no site list", old | {"holder": {"type": "agent", "id": "x"}, "bounds": {k: v for k, v in nb.items() if k != "sites"}}, ["holder", "sites"])

    no_rcpt = old | {"bounds": {k: v for k, v in nb.items() if k != "recipients"}}
    c.append({"name": "a recipient list where there was none (none meant nobody)", "op": "loosens",
              "input": {"old": no_rcpt, "new": no_rcpt | {"bounds": no_rcpt["bounds"] | {"recipients": ["@gmail.com"]}}},
              "expect": {"reasons": ["recipients"]}})
    loose("the same signer kind is not loosening", old | {"signer": {"kind": "custodial"}}, [])
    c.append({"name": "device to custodial is loosening", "op": "loosens",
              "input": {"old": old | {"signer": {"kind": "device"}}, "new": old}, "expect": {"reasons": ["signer"]}})
    loose("another issuer", old | {"iss": WALLET_ISS}, ["iss"])
    loose("dropping one payee is narrowing", old | {"bounds": nb | {"payees": ["Sweetgreen"]}}, [])
    case("two addresses hidden in one recipient", err("malformed"), action=with_args(mail(1), to=["boss@evil.test, sam@example.com"]), profile=PROFILES["send_email"])
    case("a display name hides the real address", err("malformed"), action=with_args(mail(1), to=["Sam <boss@evil.test>"]), profile=PROFILES["send_email"])
    case("a header break in an address", err("malformed"), action=with_args(mail(1), to=["boss@evil.test\r\nBcc: x@example.com"]), profile=PROFILES["send_email"])
    case("two @ signs in an address", err("malformed"), action=with_args(mail(1), to=["boss@evil.test@example.com"]), profile=PROFILES["send_email"])
    case("model adds an undeclared bcc", err("undeclared_argument"), action=with_args(mail(1), bcc=["boss@evil.test"]), profile=PROFILES["send_email"])
    case("a payment that leaves out its amount", err("malformed"), action={"tool": "pay_order", "args": {"currency": "USD", "merchant": "Sweetgreen"}}, profile=PROFILES["pay_order"])
    case("the executor acts for someone else", err("subject_mismatch"), sub="person:other")
    case("revoked or superseded", err("revoked"), revoked=["md_lunch_1"])
    case("usage counts that are not numbers", err("malformed"), usage={"calls_today": None})
    no_payees = make_mandate(key=USER, payload=body | {"bounds": {k: v for k, v in body["bounds"].items() if k != "payees"}})
    case("pay mandate without a payee list", err("pay_without_caps"), token=no_payees, action=pay, profile=PROFILES["pay_order"])
    case("a trusted signer's key signs in another signer's name", err("wrong_issuer"), token=make_mandate(key=WALLET, payload=body))
    return c


# receipts and undo
def receipts_and_undo() -> list[dict[str, Any]]:
    c: list[dict[str, Any]] = []
    rs: list[str] = []

    def add(fields: dict[str, Any], key: Any = EXEC) -> str:
        prev = token_digest(rs[-1]) if rs else None
        t = make_receipt(key=key, payload={"iss": EXECUTOR, "sub": PERSON, "seq": len(rs) + 1, "prev": prev, "iat": NOW + len(rs), **fields})
        rs.append(t)
        return t

    res = digest({"ok": True})
    task = {"tool": "add_task", "args": {"title": "Call the dentist"}}
    r1 = add({"tool": "add_task", "tier": "B", "authority": {"kind": "tier"}, "action": action_digest(task), "outcome": "ok", "result": res,
              "undo": {"kind": "native", "until": NOW + 600, "token": "undo_7Qx"}})
    book_consent = consent([pv(ACTIONS["book"], "Book Nobu Boston")])
    lunch_mandate = make_mandate(key=USER, payload={
        "id": "md_lunch_1", "iss": SIGNER, "sub": PERSON, "holder": {"type": "agent", "id": "lunch-bot"}, "goal": "Reply to lunch plans.",
        "tools": ["send_email"], "bounds": {"calls": {"per_day": 5}, "recipients": ["@example.com"]},
        "iat": NOW - 3600, "exp": NOW + 86400, "signer": {"kind": "custodial"}})

    def undo(receipt: str, mode: str, jti: str, **kw: Any) -> str:
        return make_undo(key=USER, iss=SIGNER, sub=PERSON, aud=kw.pop("aud", EXECUTOR), receipt_token=receipt, mode=mode,
                         now=kw.pop("now", NOW + 30), jti=jti, **kw)

    u1 = undo(r1, "native", "n_undo_00000000000001")
    r2 = add({"tool": "book_table", "tier": "C",
              "authority": {"kind": "consent", "ref": "n_consent_0000000001", "digest": token_digest(book_consent)},
              "action": action_digest(ACTIONS["book"]), "preview": digest(pv(ACTIONS["book"], "Book Nobu Boston")), "outcome": "ok",
              "result": res, "undo": {"kind": "compensate", "until": NOW + 86400}})
    r3 = add({"tool": "send_email", "tier": "C", "authority": {"kind": "mandate", "ref": "md_lunch_1", "digest": token_digest(lunch_mandate)},
              "action": action_digest(mail(1)),
              "outcome": "ok", "result": res, "undo": {"kind": "none"}})
    r4 = add({"tool": "add_task", "tier": "B", "authority": {"kind": "undo", "ref": "n_undo_00000000000001", "digest": token_digest(u1)},
              "action": action_digest(task),
              "outcome": "ok", "result": res, "undo": {"kind": "none"}, "undoes": token_digest(r1)})
    base = {"tokens": rs, "keys": EXEC_KEYS, "executor": EXECUTOR}

    def chain(name: str, expect: dict[str, Any], **change: Any) -> None:
        c.append({"name": name, "op": "verify_chain", "input": {**base, **change}, "expect": expect})

    chain("valid: four receipts", ok())
    chain("valid: an export starting mid-chain", ok(), tokens=[r2, r3, r4])
    chain("a receipt dropped", err("chain_seq"), tokens=[r1, r2, r4])
    chain("receipts reordered", err("chain_seq"), tokens=[r1, r3, r2, r4])
    bad_prev = sign(payload_of(r3) | {"prev": token_digest(r1)}, EXEC, RECEIPT_TYP)
    chain("prev points at the wrong receipt", err("chain_broken"), tokens=[r1, r2, bad_prev])
    chain("seq 1 with a prev", err("chain_broken"), tokens=[sign(payload_of(r1) | {"prev": token_digest(r2)}, EXEC, RECEIPT_TYP)])
    chain("signed by the executor's key but issued as someone else", err("wrong_issuer"),
          tokens=[r1, sign(payload_of(r2) | {"iss": "https://other.example/oac"}, EXEC, RECEIPT_TYP)])
    chain("a receipt from an unknown key", err("unknown_key"), tokens=[r1, sign(payload_of(r2), ATTACKER, RECEIPT_TYP)])
    chain("edited after signing", err("bad_signature"),
          tokens=[r1, r2.split(".")[0] + "." + b64url(canonical_bytes(payload_of(r2) | {"tier": "A"})) + "." + r2.split(".")[2]])
    chain("tier C on the tool's own say-so", err("receipt_invalid"),
          tokens=[r1, sign(payload_of(r2) | {"authority": {"kind": "tier"}}, EXEC, RECEIPT_TYP)])
    chain("a tier D receipt", err("receipt_invalid"), tokens=[sign(payload_of(r1) | {"tier": "D"}, EXEC, RECEIPT_TYP)])
    chain("tier authority carrying a ref", err("receipt_invalid"),
          tokens=[sign(payload_of(r1) | {"authority": {"kind": "tier", "ref": "anything"}}, EXEC, RECEIPT_TYP)])
    chain("consent authority without the digest of the exact token", err("receipt_invalid"),
          tokens=[r1, sign(payload_of(r2) | {"authority": {"kind": "consent", "ref": "n_consent_0000000001"}}, EXEC, RECEIPT_TYP)])
    chain("tier authority carrying a digest", err("receipt_invalid"),
          tokens=[sign(payload_of(r1) | {"authority": {"kind": "tier", "digest": token_digest(r1)}}, EXEC, RECEIPT_TYP)])
    chain("an export that starts mid-chain with no prev", err("chain_broken"), tokens=[sign(payload_of(r2) | {"prev": None}, EXEC, RECEIPT_TYP)])
    other = make_receipt(key=OTHER_EXEC, payload={"iss": OTHER_EXECUTOR, "sub": PERSON, "seq": 1, "prev": None, "iat": NOW, "tool": "add_task",
                         "tier": "A", "authority": {"kind": "tier"}, "action": action_digest(task), "outcome": "ok", "result": res, "undo": {"kind": "none"}})
    chain("another executor's chain, under its own trusted key", err("chain_issuer"), tokens=[other])
    chain("tier B without an undo token", err("receipt_invalid"),
          tokens=[sign(payload_of(r1) | {"undo": {"kind": "native", "until": NOW + 600}}, EXEC, RECEIPT_TYP)])

    def undo_case(name: str, expect: dict[str, Any], token: str, receipt: str, **change: Any) -> None:
        inp = {"token": token, "keys": USER_KEYS, "executor": EXECUTOR, "receipt_token": receipt, "receipt_keys": EXEC_KEYS, "now": NOW + 60}
        c.append({"name": name, "op": "check_undo", "input": inp | change, "expect": expect})

    undo_case("valid: native undo inside the window", ok(), u1, r1)
    cancel = {"tool": "cancel_booking", "args": {"restaurant": "Nobu Boston", "undoes": token_digest(r2)}}
    p_cancel = pv(cancel, "Cancel the Nobu Boston booking. No fee.", preview_id="pv_cancel")
    cancel_consent = payload_of(consent([p_cancel], jti="n_consent_0000000099"))
    comp = {"consent": cancel_consent, "action": cancel}
    undo_case("valid: compensate with a consent for the cancel", ok(),
              undo(r2, "compensate", "n_undo_00000000000002", consent="n_consent_0000000099"), r2, compensation=comp)
    undo_case("compensate with no verified consent given", err("compensation_mismatch"),
              undo(r2, "compensate", "n_undo_00000000000010", consent="n_consent_0000000099"), r2)
    other_cancel = {"tool": "cancel_booking", "args": {"restaurant": "Nobu Boston", "undoes": token_digest(r1)}}
    undo_case("the cancel consent is for undoing another receipt", err("compensation_mismatch"),
              undo(r2, "compensate", "n_undo_00000000000011", consent="n_consent_0000000099"), r2,
              compensation={"consent": cancel_consent, "action": other_cancel})
    undo_case("the request names a different consent than the one given", err("compensation_mismatch"),
              undo(r2, "compensate", "n_undo_00000000000012", consent="n_consent_0000000098"), r2, compensation=comp)
    undo_case("already undone", err("already_undone"), u1, r1, undone=[token_digest(r1)])
    undo_case("a receipt for another person", err("subject_mismatch"),
              make_undo(key=USER, iss=SIGNER, sub="person:other", aud=EXECUTOR, receipt_token=r1, mode="native", now=NOW + 30,
                        jti="n_undo_00000000000013"), r1)
    undo_case("window closed", err("undo_window_closed"), undo(r1, "native", "n_undo_00000000000008", now=NOW + 590), r1, now=NOW + 601)
    undo_case("a sent email cannot be undone", err("not_reversible"), undo(r3, "native", "n_undo_00000000000003"), r3)
    undo_case("native undo asked of a compensate action", err("undo_mode_mismatch"), undo(r2, "native", "n_undo_00000000000004"), r2)
    undo_case("compensate without a consent for the new action", err("malformed"), undo(r2, "compensate", "n_undo_00000000000005"), r2)
    undo_case("undo names one receipt, another is given", err("receipt_mismatch"), u1, r2)
    undo_case("replayed undo", err("replay"), u1, r1, seen_nonces=["n_undo_00000000000001"])
    undo_case("undo sent to another executor", err("wrong_audience"), undo(r1, "native", "n_undo_00000000000006", aud="https://other.example/oac"), r1)
    self_approved = sign(payload_of(r2) | {"authority": {"kind": "tier"}}, EXEC, RECEIPT_TYP)
    undo_case("undo of an invalid receipt (tier C on its own say-so)", err("receipt_invalid"),
              undo(self_approved, "compensate", "n_undo_00000000000009", consent="n_consent_0000000098"), self_approved)
    failed = sign(payload_of(r1) | {"outcome": "failed"}, EXEC, RECEIPT_TYP)
    undo_case("nothing to undo when the action failed", err("not_reversible"), undo(failed, "native", "n_undo_00000000000007"), failed)
    c.extend(occurrences())
    return c


def occurrences() -> list[dict[str, Any]]:
    """A payment that timed out, then a fresh consent for the same order (spec 5.1)."""
    c: list[dict[str, Any]] = []
    for state, want in [(None, ok()), ("failed", ok()), ("running", err("occurrence_unresolved")),
                        ("unknown", err("occurrence_unresolved")), ("ok", err("duplicate_occurrence"))]:
        c.append({"name": f"claim an occurrence whose last attempt is {state or 'new'}", "op": "claim_occurrence",
                  "input": {"state": state}, "expect": want})
    rs: list[str] = []
    pay = ACTIONS["pay"]

    def add(outcome: str, jti: str) -> str:
        token = consent([pv(pay, "Pay Sweetgreen $18.00")], jti=jti)
        undo = {"kind": "compensate", "until": NOW + 604800} if outcome == "ok" else {"kind": "compensate"}
        t = make_receipt(key=EXEC, payload={
            "iss": EXECUTOR, "sub": PERSON, "seq": len(rs) + 1, "prev": token_digest(rs[-1]) if rs else None, "iat": NOW + len(rs),
            "tool": "pay_order", "tier": "C", "authority": {"kind": "consent", "ref": jti, "digest": token_digest(token)},
            "action": action_digest(pay), "outcome": outcome, "result": digest(None), "undo": undo, "occurrence": "ord_2231"})
        rs.append(t)
        return t

    timeout, retry, again = add("unknown", "n_consent_0000000040"), add("ok", "n_consent_0000000041"), add("ok", "n_consent_0000000042")
    base = {"keys": EXEC_KEYS, "executor": EXECUTOR}
    c.append({"name": "valid: a timeout, then a retry after it was resolved as failed", "op": "verify_chain",
              "input": base | {"tokens": [timeout, retry]}, "expect": ok()})
    c.append({"name": "the same order paid twice under two fresh consents", "op": "verify_chain",
              "input": base | {"tokens": [timeout, retry, again]}, "expect": err("duplicate_occurrence")})
    refund_request = make_undo(key=USER, iss=SIGNER, sub=PERSON, aud=EXECUTOR, receipt_token=retry, mode="compensate",
                               now=NOW + 1, jti="n_undo_00000000000040", consent="n_consent_0000000043")
    refund = make_receipt(key=EXEC, payload={
        "iss": EXECUTOR, "sub": PERSON, "seq": 3, "prev": token_digest(retry), "iat": NOW + 2, "tool": "pay_order", "tier": "C",
        "authority": {"kind": "undo", "ref": "n_undo_00000000000040", "digest": token_digest(refund_request)}, "action": action_digest(pay),
        "outcome": "ok", "result": digest(None), "undo": {"kind": "none"}, "undoes": token_digest(retry), "occurrence": "ord_2231"})
    c.append({"name": "valid: an undo receipt for a paid order is not a second payment", "op": "verify_chain",
              "input": base | {"tokens": [timeout, retry, refund]}, "expect": ok()})
    return c


# status lists, key discovery, seals
def gap_closers() -> list[dict[str, Any]]:
    import gzip

    c: list[dict[str, Any]] = []
    enc = encode([0, 7, 9, 131071])
    for name, idx, want in [("index 0 is the left-most bit", 0, True), ("an unset bit", 1, False), ("bit 7 (end of the first byte)", 7, True),
                            ("bit 9 (second byte)", 9, True), ("the last bit of a 16 KB list", 131071, True)]:
        c.append({"name": f"status list: {name}", "op": "status_bit", "input": {"encoded_list": enc, "index": idx}, "expect": {"revoked": want}})
    raw = bytes(16 * 1024)
    bad = [("index past the end", enc, 131072),
           ("no multibase prefix", enc[1:], 0),
           ("shorter than 16 KB", "u" + b64url(gzip.compress(bytes(1024), mtime=0)), 0),
           ("inflates past 2 MB (zip bomb)", "u" + b64url(gzip.compress(bytes(3 * 1024 * 1024), mtime=0)), 0),
           ("two gzip members", "u" + b64url(gzip.compress(raw, mtime=0) + gzip.compress(raw, mtime=0)), 0),
           ("bytes after the gzip member", "u" + b64url(gzip.compress(raw, mtime=0) + bytes(4)), 0),
           ("not gzip", "u" + b64url(raw), 0)]
    for name, e, idx in bad:
        c.append({"name": f"status list: {name}", "op": "status_bit", "input": {"encoded_list": e, "index": idx}, "expect": err("malformed")})

    holder = {"type": "agent", "id": "lunch-bot"}
    lid = "https://atlas.example/signer/status/1"
    body = {"id": "md_status_1", "iss": SIGNER, "sub": PERSON, "holder": holder, "goal": "Book lunch.", "tools": ["book_table"],
            "bounds": {"calls": {"per_day": 5}, "sites": ["nobu.example"]}, "iat": NOW - 3600, "exp": NOW + 86400,
            "signer": {"kind": "custodial"}, "status": {"list": lid, "index": 42}}
    m = make_mandate(key=USER, payload=body)
    live = make_status_list(key=USER, iss=SIGNER, list_id=lid, revoked=[41, 43], now=NOW - 60)
    gone = make_status_list(key=USER, iss=SIGNER, list_id=lid, revoked=[42], now=NOW - 60)
    base = {"token": m, "keys": USER_KEYS, "action": ACTIONS["book"], "profile": PROFILES["book_table"], "holder": holder, "sub": PERSON,
            "now": NOW, "tainted": False}

    def case(name: str, expect: dict[str, Any], **change: Any) -> None:
        c.append({"name": name, "op": "check_mandate", "input": {**base, **change}, "expect": expect})

    case("status list: the mandate's bit is clear", ok(), status_lists={lid: live})
    case("status list: the mandate's bit is set (revoked)", err("revoked"), status_lists={lid: gone})
    case("status list: the list is not available", err("status_unknown"))
    case("status list: the list is stale", err("status_unknown"), status_lists={lid: make_status_list(key=USER, iss=SIGNER, list_id=lid, revoked=[], now=NOW - 7200, ttl=3600)})
    case("status list: another list given under this id", err("status_unknown"),
         status_lists={lid: make_status_list(key=USER, iss=SIGNER, list_id="https://atlas.example/signer/status/2", revoked=[], now=NOW - 60)})
    case("status list: signed by another trusted signer", err("status_unknown"),
         status_lists={lid: make_status_list(key=WALLET, iss=WALLET_ISS, list_id=lid, revoked=[], now=NOW - 60)})
    case("status list: claims the mandate's signer but uses another key", err("wrong_issuer"),
         status_lists={lid: make_status_list(key=WALLET, iss=SIGNER, list_id=lid, revoked=[], now=NOW - 60)})

    for name, iss, want in [("an issuer with a path", "https://atlas.example/signer", {"url": "https://atlas.example/.well-known/oac-issuer/signer"}),
                            ("an issuer without a path", "https://wallet.example", {"url": "https://wallet.example/.well-known/oac-issuer"}),
                            ("a port is kept", "https://atlas.example:8443/s", {"url": "https://atlas.example:8443/.well-known/oac-issuer/s"}),
                            ("http is refused", "http://atlas.example/signer", err("malformed")),
                            ("a query is refused", "https://atlas.example/signer?x=1", err("malformed")),
                            ("credentials are refused", "https://u:p@atlas.example/signer", err("malformed")),
                            ("not a URL", "person:7f3a", err("malformed")),
                            ("a trailing slash is dropped", "https://atlas.example/signer/", {"url": "https://atlas.example/.well-known/oac-issuer/signer"}),
                            ("port 443 is kept as written", "https://atlas.example:443", {"url": "https://atlas.example:443/.well-known/oac-issuer"}),
                            ("an uppercase host is refused", "https://Atlas.example/signer", err("malformed")),
                            ("a non-ASCII host is refused", "https://ätlas.example", err("malformed")),
                            ("a fragment is refused", "https://atlas.example/signer#x", err("malformed")),
                            ("a dot-dot path segment is refused", "https://atlas.example/a/../b", err("malformed")),
                            ("a single-dot segment is refused", "https://atlas.example/./b", err("malformed")),
                            ("dots inside a segment are fine", "https://atlas.example/v1.2", {"url": "https://atlas.example/.well-known/oac-issuer/v1.2"})]:
        c.append({"name": f"issuer metadata URL: {name}", "op": "metadata_url", "input": {"iss": iss}, "expect": want})
    meta = {"oac": "0.1", "type": "issuer-metadata", "issuer": SIGNER, "keys": [USER.jwk, DEVICE.jwk], "status_lists": [lid]}
    c.append({"name": "issuer metadata: keys become that issuer's", "op": "keyset_from", "input": {"docs": [[SIGNER, meta]], "kid": DEVICE.kid}, "expect": {"issuer": SIGNER}})
    c.append({"name": "issuer metadata: a document naming another issuer", "op": "keyset_from", "input": {"docs": [[WALLET_ISS, meta]], "kid": USER.kid}, "expect": err("wrong_issuer")})
    c.append({"name": "issuer metadata: a private key member is refused", "op": "keyset_from",
              "input": {"docs": [[SIGNER, meta | {"keys": [USER.jwk | {"d": "AAAA"}]}]], "kid": USER.kid}, "expect": err("malformed")})
    c.append({"name": "issuer metadata: one key claimed by two issuers", "op": "keyset_from",
              "input": {"docs": [[SIGNER, meta], [WALLET_ISS, meta | {"issuer": WALLET_ISS}]], "kid": USER.kid}, "expect": err("malformed")})

    rs: list[str] = []
    res = digest({"ok": True})
    task = {"tool": "add_task", "args": {"title": "Call the dentist"}}
    for n in range(3):
        rs.append(make_receipt(key=EXEC, payload={"iss": EXECUTOR, "sub": PERSON, "seq": n + 1, "prev": token_digest(rs[-1]) if rs else None,
                  "iat": NOW + n, "tool": "add_task", "tier": "A", "authority": {"kind": "tier"}, "action": action_digest(task),
                  "outcome": "ok", "result": res, "undo": {"kind": "none"}}))
    seal = make_seal(key=USER, iss=SIGNER, sub=PERSON, executor=EXECUTOR, seq=3, head_token=rs[2], now=NOW + 10)
    sbase = {"tokens": rs, "keys": EXEC_KEYS, "executor": EXECUTOR, "seals": [seal], "seal_keys": USER_KEYS}
    forged_r3 = make_receipt(key=EXEC, payload=payload_of(rs[2]) | {"tool": "add_task", "iat": NOW + 99})

    def chain(name: str, expect: dict[str, Any], **change: Any) -> None:
        c.append({"name": name, "op": "verify_chain", "input": {**sbase, **change}, "expect": expect})

    chain("seal: matches the chain head", ok())
    chain("seal: the executor rewrote receipt 3 after the seal", err("seal_mismatch"), tokens=[rs[0], rs[1], forged_r3])
    chain("seal: names a receipt the export does not contain", err("seal_mismatch"), tokens=rs[:2])
    chain("seal: for another executor", err("seal_mismatch"),
          seals=[make_seal(key=USER, iss=SIGNER, sub=PERSON, executor=OTHER_EXECUTOR, seq=3, head_token=rs[2], now=NOW + 10)])
    chain("seal: for another person", err("subject_mismatch"),
          seals=[make_seal(key=USER, iss=SIGNER, sub="person:other", executor=EXECUTOR, seq=3, head_token=rs[2], now=NOW + 10)])
    chain("seal: signed by an unknown key", err("unknown_key"),
          seals=[make_seal(key=ATTACKER, iss=SIGNER, sub=PERSON, executor=EXECUTOR, seq=3, head_token=rs[2], now=NOW + 10)])
    return c


def main() -> int:
    out = ROOT / "vectors"
    out.mkdir(exist_ok=True)
    groups = {"basics": basics(), "consent": consents(), "mandate": mandates(), "receipts-undo": receipts_and_undo(),
              "status-keys-seals": gap_closers()}
    bad = 0
    for name, cases in groups.items():
        for case in cases:
            got = run_case(case)
            if got != case["expect"]:
                bad += 1
                print(f"SDK DISAGREES {name} :: {case['name']}: expected {case['expect']}, got {got}")
        doc = {"oac": shapes.VERSION, "about": f"OAC v0.1 conformance vectors: {name}. Keys: oac.testing.vector_key labels "
               "(test only). Time is unix seconds; NOW = 1793836800.", "cases": cases}
        (out / f"{name}.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    total = sum(len(v) for v in groups.values())
    print(f"wrote {total} cases; SDK disagreements: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
