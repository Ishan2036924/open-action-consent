"""Property-based fuzzing of every surface that reads untrusted input.

The rule each property checks: a hostile input is refused with OACError and a known code, never another exception,
and the well-formed path round-trips. Runs are seeded (derandomize) so CI is repeatable; OAC_FUZZ_EXAMPLES raises the
budget for a longer local or nightly run, for example OAC_FUZZ_EXAMPLES=5000 python -m pytest tests/test_fuzz.py.
"""

from __future__ import annotations

import base64
import json
import os
import random
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from oac import (  # noqa: E402
    CODES,
    KeySet,
    OACError,
    action_digest,
    assess,
    canonical,
    digest,
    make_observation,
    make_receipt,
    make_seal,
    parse,
    shapes,
    token_digest,
    verify,
    verify_chain,
    verify_export,
)
from oac.jws import _signature, b64url  # noqa: E402
from oac.receipts import check_semantics  # noqa: E402
from oac.testing import vector_key  # noqa: E402

EXAMPLES = int(os.environ.get("OAC_FUZZ_EXAMPLES", "100"))
FUZZ = settings(max_examples=EXAMPLES, derandomize=True, deadline=None, database=None,
                suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
SAFE = 2**53 - 1

EX, SIGNER, SEER_ISS, PERSON, NOW = "https://shop.example/oac", "https://signer.example", "https://seer.example", "person:1", 1_800_000_000
EXEC, USER, SEER = vector_key("fuzz executor"), vector_key("fuzz signer"), vector_key("fuzz observer", "ES256")
KEYS, USER_KEYS, SEER_KEYS = KeySet({EX: [EXEC.jwk]}), KeySet({SIGNER: [USER.jwk]}), KeySet({SEER_ISS: [SEER.jwk]})
TASK = {"tool": "add_task", "args": {"title": "Call"}}
RES = digest({"ok": True})


def receipt(n: int, prev: str | None, **fields: Any) -> str:
    base = {"iss": EX, "sub": PERSON, "seq": n, "prev": prev, "iat": NOW + n, "tool": "add_task", "tier": "A",
            "authority": {"kind": "tier"}, "action": action_digest(TASK), "outcome": "ok", "result": RES,
            "undo": {"kind": "none"}}
    return make_receipt(key=EXEC, payload=base | fields)


CHAIN: list[str] = []
for _i in range(1, 5):
    CHAIN.append(receipt(_i, token_digest(CHAIN[-1]) if CHAIN else None))
SEALS = [make_seal(key=USER, iss=SIGNER, sub=PERSON, executor=EX, seq=i, head_token=CHAIN[i - 1], now=NOW)
         for i in range(1, 5)]
OBS = [make_observation(key=SEER, iss=SEER_ISS, sub=PERSON, executor=EX, receipt_token=CHAIN[0], effect=e, now=NOW + 5)
       for e in ("seen", "not_seen", "uncheckable")]
VALID_RECEIPT = parse(base64.urlsafe_b64decode(CHAIN[0].split(".")[1] + "=="))
VALID_SEAL = parse(base64.urlsafe_b64decode(SEALS[0].split(".")[1] + "=="))
VALID_OBS = parse(base64.urlsafe_b64decode(OBS[0].split(".")[1] + "=="))


def refused(f, *a: Any, **kw: Any) -> Any:
    """Run f; an OACError with a known code is a fine answer, anything else fails the property."""
    try:
        return f(*a, **kw)
    except OACError as e:
        assert e.code in CODES
        return e


# Strategies

scalars = st.none() | st.booleans() | st.integers(-SAFE, SAFE) | st.text(max_size=20)
json_values = st.recursive(
    scalars,
    lambda inner: st.lists(inner, max_size=5) | st.dictionaries(st.text(max_size=10), inner, max_size=5),
    max_leaves=25,
)
# what a hostile caller can hand over that JSON cannot express
python_values = st.recursive(
    scalars | st.floats(allow_nan=True) | st.integers() | st.binary(max_size=8)
    | st.text(alphabet=st.characters(codec=None, categories=["Cs", "Lu", "Ll"]), max_size=4),
    lambda inner: st.lists(inner, max_size=4) | st.tuples(inner) | st.dictionaries(scalars, inner, max_size=4),
    max_leaves=15,
)


@st.composite
def mutated(draw, text: str) -> str:
    """A small edit of a valid string: insert, delete, replace or swap at a drawn position."""
    if not text:
        return draw(st.text(max_size=4))
    i = draw(st.integers(0, len(text) - 1))
    op = draw(st.sampled_from(["insert", "delete", "replace", "swap", "truncate"]))
    c = draw(st.characters(codec=None) | st.sampled_from(list('{}[]",:.\\-0123456789eE AaZz_=')))
    if op == "insert":
        return text[:i] + c + text[i:]
    if op == "delete":
        return text[:i] + text[i + 1:]
    if op == "replace":
        return text[:i] + c + text[i + 1:]
    if op == "swap" and i + 1 < len(text):
        return text[:i] + text[i + 1] + text[i] + text[i + 2:]
    return text[:i]


# Strict JSON and JCS


@FUZZ
@given(json_values)
def test_jcs_round_trip_and_idempotent(v: Any) -> None:
    c = canonical(v)
    assert parse(c) == v
    assert canonical(parse(c)) == c
    assert parse(c.encode("utf-8")) == v


@FUZZ
@given(python_values)
def test_canonical_refuses_only_with_oac_error(v: Any) -> None:
    out = refused(canonical, v)
    if isinstance(out, str):
        assert canonical(parse(out)) == out


@FUZZ
@given(st.text(max_size=60) | st.binary(max_size=60).map(lambda b: b.decode("latin-1")))
def test_parse_arbitrary_text(text: str) -> None:
    out = refused(parse, text)
    if not isinstance(out, OACError):
        canonical(out)  # whatever parse accepts is in the canonical subset


@FUZZ
@given(st.binary(max_size=80))
def test_parse_arbitrary_bytes(data: bytes) -> None:
    refused(parse, data)


@FUZZ
@given(json_values.flatmap(lambda v: mutated(canonical(v))))
def test_parse_near_misses(text: str) -> None:
    out = refused(parse, text)
    if not isinstance(out, OACError):
        assert canonical(parse(canonical(out))) == canonical(out)


@FUZZ
@given(st.integers(1, 200), st.sampled_from(["[", '{"a":']))
def test_parse_deep_nesting(depth: int, opener: str) -> None:
    closer = "]" if opener == "[" else "}"
    out = refused(parse, opener * depth + "1" + closer * depth)
    assert isinstance(out, OACError) == (depth > 64)


# Compact JWS


def b64json(v: Any) -> str:
    return b64url(json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode("utf-8", "surrogatepass"))


tokens = (
    st.text(max_size=80)
    | st.sampled_from(CHAIN + SEALS + OBS).flatmap(mutated)
    | st.tuples(json_values, json_values, st.binary(max_size=70)).map(
        lambda t: b64json(t[0]) + "." + b64json(t[1]) + "." + b64url(t[2]))
    | st.tuples(st.sampled_from(["EdDSA", "ES256", "none", "HS256"]), st.sampled_from([EXEC.kid, SEER.kid, "x"]),
                json_values, st.binary(max_size=70)).map(
        lambda t: b64url(canonical({"alg": t[0], "kid": t[1], "typ": "oac-receipt+jws"}).encode()) + "."
        + b64json(t[2]) + "." + b64url(t[3]))
    | st.lists(st.sampled_from(["", "e30", "eyJ9", "AA", "_-", "=", ".", "A" * 5]), max_size=5).map(".".join)
)


@FUZZ
@given(tokens, st.sampled_from(["oac-receipt+jws", "oac-seal+jws", "oac-observation+jws"]))
def test_verify_refuses_hostile_tokens(token: str, typ: str) -> None:
    keys = KeySet({EX: [EXEC.jwk], SIGNER: [USER.jwk], SEER_ISS: [SEER.jwk]})
    out = refused(verify, token, keys, typ)
    if not isinstance(out, OACError):
        assert token in CHAIN + SEALS + OBS  # only an untouched token verifies


@FUZZ
@given(st.sampled_from(CHAIN).flatmap(mutated))
def test_any_edit_of_a_signed_token_is_refused(token: str) -> None:
    if token not in CHAIN:
        assert isinstance(refused(verify, token, KEYS, "oac-receipt+jws"), OACError)


jwk_like = st.fixed_dictionaries(
    {},
    optional={
        "kty": st.sampled_from(["OKP", "EC", "RSA"]) | json_values,
        "crv": st.sampled_from(["Ed25519", "P-256", "X25519"]) | json_values,
        "x": st.sampled_from([EXEC.jwk["x"], SEER.jwk["x"], "", "AA"]) | json_values,
        "y": st.sampled_from([SEER.jwk.get("y", ""), ""]) | json_values,
        "kid": st.sampled_from([EXEC.kid, SEER.kid]) | json_values,
    },
)


@FUZZ
@given(st.dictionaries(st.text(max_size=6), python_values, max_size=6) | jwk_like | python_values,
       st.sampled_from(["list", "bare", "whole"]))
def test_keyset_refuses_hostile_jwks(jwk: Any, how: str) -> None:
    # issuer key documents come from the network: only OACError, never a KeyError or TypeError
    refused(KeySet, {"list": {"iss": [jwk]}, "bare": {"iss": jwk}, "whole": jwk}[how])


@FUZZ
@given(jwk_like, st.sampled_from(CHAIN + SEALS + OBS))
def test_verify_with_a_hostile_trusted_key(jwk: dict, token: str) -> None:
    keys = refused(KeySet, {EX: [jwk]})
    if isinstance(keys, KeySet):
        refused(verify, token, keys, "oac-receipt+jws")


# Shape checks: receipt, seal, observation


@st.composite
def damaged(draw, doc: dict) -> Any:
    """A valid object with one field dropped, replaced by any JSON value, or a field added."""
    d = dict(doc)
    op = draw(st.sampled_from(["drop", "replace", "add", "whole"]))
    if op == "whole":
        return draw(json_values)
    if op == "add":
        d[draw(st.text(max_size=8))] = draw(json_values)
        return d
    k = draw(st.sampled_from(sorted(d)))
    if op == "drop":
        del d[k]
    else:
        d[k] = draw(json_values | st.dictionaries(st.sampled_from(["kind", "ref", "digest", "until", "token"]),
                                                   json_values, max_size=3))
    return d


@FUZZ
@given(damaged(VALID_RECEIPT))
def test_receipt_shape(v: Any) -> None:
    out = refused(shapes.receipt, v)
    if not isinstance(out, OACError):
        refused(check_semantics, out)


@FUZZ
@given(damaged(VALID_SEAL))
def test_seal_shape(v: Any) -> None:
    refused(shapes.seal, v)


@FUZZ
@given(damaged(VALID_OBS))
def test_observation_shape(v: Any) -> None:
    refused(shapes.observation, v)


# verify_export and assess


def signed(doc: Any, key, typ: str) -> str:
    """A hostile payload under a trusted key: the signature is good, so only the field checks stand in the way."""
    head = b64url(canonical({"alg": key.alg, "kid": key.kid, "typ": typ}).encode())
    body = b64url(canonical(doc).encode("utf-8"))
    return head + "." + body + "." + b64url(_signature(key, (head + "." + body).encode("ascii")))


trusted_garbage = st.one_of(
    damaged(VALID_RECEIPT).map(lambda d: signed(d if not isinstance(d, dict) else {**d, "iss": EX}, EXEC, "oac-receipt+jws")),
    damaged(VALID_SEAL).map(lambda d: signed(d if not isinstance(d, dict) else {**d, "iss": SIGNER}, USER, "oac-seal+jws")),
    damaged(VALID_OBS).map(lambda d: signed(d if not isinstance(d, dict) else {**d, "iss": SEER_ISS}, SEER,
                                            "oac-observation+jws")),
)
any_token = tokens | trusted_garbage | st.sampled_from(CHAIN + SEALS + OBS)
token_lists = st.lists(any_token, max_size=5) | st.permutations(CHAIN).map(list) | json_values


@FUZZ
@given(token_lists, token_lists, st.none() | json_values | st.fixed_dictionaries(
    {"seq": st.integers(-2, 8)}, optional={"head": st.sampled_from([token_digest(t) for t in CHAIN]) | st.text(max_size=5)}))
def test_verify_export_on_hostile_input(toks: Any, anchors: Any, expect: Any) -> None:
    out = refused(verify_export, toks, keys=KEYS, executor=EX, anchors=anchors, anchor_keys=USER_KEYS, expect=expect)
    if not isinstance(out, OACError):
        assert out["status"] in ("complete", "prefix")


@FUZZ
@given(st.lists(st.sampled_from(SEALS) | any_token, max_size=4))
def test_verify_chain_seals_on_hostile_input(seals: list) -> None:
    refused(verify_chain, CHAIN, keys=KEYS, executor=EX, seals=seals, seal_keys=USER_KEYS)


@FUZZ
@given(any_token, st.lists(st.sampled_from(OBS) | any_token, max_size=4) | json_values, st.none() | any_token)
def test_assess_on_hostile_input(rec: Any, observations: Any, authority: Any) -> None:
    out = refused(assess, rec, keys=KEYS, executor=EX, observations=observations, observer_keys=SEER_KEYS,
                  authority_token=authority, authority_keys=USER_KEYS)
    if not isinstance(out, OACError):
        assert out["verdict"] in ("pass", "fail", "cannot_establish")


@FUZZ
@given(st.sampled_from(["consent", "mandate", "undo"]), json_values, st.sampled_from(["oac-consent+jws", "oac-mandate+jws",
                                                                                    "oac-undo+jws"]))
def test_assess_with_a_trusted_but_hostile_authority(kind: str, payload: Any, typ: str) -> None:
    auth = signed({**payload, "iss": SIGNER} if isinstance(payload, dict) else payload, USER, typ)
    rec = receipt(1, None, tier="C", authority={"kind": kind, "ref": "r-1", "digest": token_digest(auth)},
                  **({"undoes": RES} if kind == "undo" else {}))
    refused(assess, rec, keys=KEYS, executor=EX, authority_token=auth, authority_keys=USER_KEYS)


# Python and TypeScript agree on JCS


def _corpus(seed: int, n: int) -> list[bytes]:
    """Seeded JSON texts: valid values with awkward strings and keys, plus near misses of them."""
    rng = random.Random(seed)
    alphabet = ["a", "Z", "0", " ", "\"", "\\", "/", "\x00", "\x1f", "\x7f", "é", " ", "﻿", "￿",
                "\U0001f600", "\U00010000", "퟿", ""]

    def text() -> str:
        return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 6)))

    def value(depth: int = 0) -> Any:
        r = rng.random()
        if depth > 4 or r < 0.4:
            return rng.choice([None, True, False, rng.randint(-SAFE, SAFE), rng.randint(-1000, 1000), text()])
        if r < 0.7:
            return [value(depth + 1) for _ in range(rng.randint(0, 4))]
        return {text(): value(depth + 1) for _ in range(rng.randint(0, 4))}

    out: list[bytes] = []
    for _ in range(n):
        v = value()
        style = rng.random()
        if style < 0.4:
            raw = canonical(v)
        elif style < 0.7:  # the same value spelled another way: escapes, spaces, key order
            raw = json.dumps(v, ensure_ascii=rng.random() < 0.5, indent=rng.choice([None, 1]), sort_keys=rng.random() < 0.5)
        else:
            raw = canonical(v)
            i = rng.randint(0, len(raw))
            raw = raw[:i] + rng.choice(["", ",", "-", "0", "1.5", "e1", "\\u", "\\ud800", "\"", "}", "]", " ", "\t", "NaN"]) + raw[i + rng.randint(0, 2):]
        out.append(raw.encode("utf-8", "surrogatepass"))
    out += [b"\xef\xbb\xbf{}", b"\xed\xa0\x80", b'"\\ud83d\\ude00"', b'"\\uD83D"', b"-0", b"9007199254740992",
            b"-9007199254740991", b"[1,]", b'{"a":1,"a":1}', b" [ ] ", b"\x00"]
    return out


def test_python_and_typescript_agree_on_jcs(tmp_path: Path) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    major, minor = (int(x) for x in subprocess.run([node, "-p", "process.versions.node"], capture_output=True, text=True,
                                                   check=True).stdout.split(".")[:2])
    if (major, minor) < (23, 6):
        pytest.skip("node 23.6 or newer runs the TypeScript sources")
    jcs_ts = Path(__file__).resolve().parents[2] / "typescript" / "src" / "jcs.ts"
    n = max(400, EXAMPLES * 4)
    corpus = _corpus(20261121, n)
    (tmp_path / "in.json").write_text(json.dumps([base64.b64encode(b).decode() for b in corpus]))
    script = tmp_path / "jcs.mjs"
    script.write_text(
        f"import {{ canonical, parse }} from {json.dumps(jcs_ts.as_uri())};\n"
        "import * as fs from 'node:fs';\n"
        "const inputs = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));\n"
        "const out = inputs.map((b) => { try { return canonical(parse(Buffer.from(b, 'base64'))); }"
        " catch (e) { return 'ERR:' + e.code; } });\n"
        "fs.writeFileSync(process.argv[3], JSON.stringify(out));\n"
    )
    subprocess.run([node, str(script), str(tmp_path / "in.json"), str(tmp_path / "out.json")], check=True, timeout=120)
    ts = json.loads((tmp_path / "out.json").read_text())
    accepted = 0
    for raw, theirs in zip(corpus, ts, strict=True):
        try:
            ours = canonical(parse(raw))
            accepted += 1
        except OACError as e:
            ours = "ERR:" + e.code
        assert ours == theirs, raw
    assert accepted > n // 4  # the corpus exercises the accepting path, not only refusals


# The gate: what an agent, a gateway (LiteLLM) or a page hands it is untrusted


GATE_PROFILES = {
    "notes/read_note": {"effect": "read", "binds": {"title": "title"}},
    "tasks/add_task": {"effect": "write", "undo": "native", "window_s": 600, "binds": {"title": "title"}},
    "mail/send_email": {"effect": "send", "binds": {"to": "to", "title": "subject"}, "other_args": ["body"]},
    "files/wipe_drive": {"effect": "delete", "tier_floor": "D", "binds": {"title": "drive"}},
    "shop/order": {"effect": "write", "undo": "native", "window_s": 60, "binds": {"title": "item"},
                   "other_args": ["order_id"], "occurrence": "order_id", "occurrence_scope": "shop"},
}
ARG_NAMES = ["title", "to", "subject", "body", "drive", "item", "order_id", "x", "__proto__", ""]


def _gate():
    from oac.gate import Gate

    gate = Gate(executor=EX, key=EXEC, signers=USER_KEYS, clock=lambda: NOW)
    for tool, p in GATE_PROFILES.items():
        gate.profile(tool, **p)
    return gate


hostile_args = st.sampled_from([{"title": "Call"}, {"to": ["pat@example.org"], "subject": "Hi", "body": "x"},
                                {"item": "tea", "order_id": "o-1"}, {"drive": "C"}]) | st.dictionaries(st.sampled_from(ARG_NAMES) | st.text(max_size=6), python_values, max_size=5) | st.fixed_dictionaries(
    {"title": st.text(max_size=30)}, optional={"order_id": json_values, "to": json_values, "subject": json_values,
                                               "item": json_values, "body": json_values})


@FUZZ
@given(st.sampled_from(sorted(GATE_PROFILES)) | st.text(max_size=12), hostile_args,
       st.sampled_from([PERSON, "user_id:alice"]) | st.text(max_size=12), st.booleans(), python_values)
def test_gate_refuses_before_running_or_writes_a_receipt(tool: str, args: dict, person: str, tainted: bool,
                                                         result: Any) -> None:
    # an action either is refused before it runs, or runs and gets a receipt: never runs without one
    from oac.gate import NeedsConsent

    gate, ran = _gate(), []
    try:
        out, receipt_token = gate.run(tool, args, lambda **kw: ran.append(kw) or result, person=person, tainted=tainted)
    except NeedsConsent as ask:
        assert not ran and shapes.preview(ask.preview)
        return
    except OACError as e:
        assert not ran and e.code in CODES
        return
    assert ran and out is result
    assert verify_chain([receipt_token], keys=KEYS, executor=EX)[0]["sub"] == person


@FUZZ
@given(any_token | python_values, st.none() | json_values | python_values)
def test_gate_accept_consent_never_raises(token: Any, proof: Any) -> None:
    # the LiteLLM intake endpoint and the x-oac-consent header hand these over as they arrive
    gate = _gate()
    gate.preview("mail/send_email", {"to": ["pat@example.org"], "subject": "Hi", "body": "x"}, person=PERSON)
    assert gate.accept_consent(token, proof) in (True, False)
