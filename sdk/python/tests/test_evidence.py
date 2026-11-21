"""Completeness anchors, observations and coverage (spec 8.4, 8.5, 13.2): each refusal and each verdict branch is pinned here."""

from __future__ import annotations

import pytest

from oac import (KeySet, OACError, action_digest, assess, build_preview, coverage, digest, generate, make_consent, make_observation,
                 make_receipt, make_seal, token_digest, verify_chain, verify_export)

EX, SIGNER, PROVIDER, PERSON, NOW = "https://shop.example/oac", "https://atlas.example/signer", "https://provider.example", "person:1", 1_800_000_000
EXEC, USER, SEER = generate(), generate(), generate()
KEYS, USER_KEYS, SEER_KEYS = KeySet({EX: [EXEC.jwk]}), KeySet({SIGNER: [USER.jwk]}), KeySet({PROVIDER: [SEER.jwk]})
TASK = {"tool": "add_task", "args": {"title": "Call"}}
RES = digest({"ok": True})


def receipt(n: int = 1, prev: str | None = None, **fields) -> str:
    base = {"iss": EX, "sub": PERSON, "seq": n, "prev": prev, "iat": NOW + n, "tool": "add_task", "tier": "A", "authority": {"kind": "tier"},
            "action": action_digest(TASK), "outcome": "ok", "result": RES, "undo": {"kind": "none"}}
    return make_receipt(key=EXEC, payload=base | fields)


def chain(n: int = 6) -> list[str]:
    out: list[str] = []
    for i in range(1, n + 1):
        out.append(receipt(i, token_digest(out[-1]) if out else None))
    return out


RS = chain()


def anchor(n: int, key=USER, iss: str = SIGNER, **kw) -> str:
    return make_seal(key=key, iss=iss, sub=kw.get("sub", PERSON), executor=kw.get("executor", EX), seq=n, head_token=kw.get("head", RS[n - 1]), now=NOW)


def export(tokens: list[str], *anchors: str, **kw) -> dict:
    return verify_export(tokens, keys=KEYS, executor=EX, anchors=list(anchors), anchor_keys=kw.pop("anchor_keys", USER_KEYS), **kw)


def code(f, *a, **kw) -> str:
    with pytest.raises(OACError) as e:
        f(*a, **kw)
    return e.value.code


def test_six_cut_to_four_verifies_as_a_chain_but_is_only_a_prefix() -> None:
    assert len(verify_chain(RS[:4], keys=KEYS, executor=EX)) == 4  # the chain alone cannot tell
    assert export(RS[:4]) == {"first": 1, "last": 4, "proven_to": None, "status": "prefix", "reason": "no_anchor"}


def test_an_anchor_beyond_the_export_says_it_was_cut() -> None:
    assert code(export, RS[:4], anchor(6)) == "chain_truncated"
    assert code(export, [], anchor(1)) == "chain_truncated"


def test_the_verifiers_own_count_says_it_was_cut() -> None:
    assert code(export, RS[:4], expect={"seq": 6}) == "chain_truncated"
    assert code(export, RS[:4], expect={"seq": 4, "head": token_digest(RS[2])}) == "seal_mismatch"
    assert export(RS[:4], expect={"seq": 4, "head": token_digest(RS[3])})["status"] == "prefix"  # a count refuses; it does not prove
    assert code(export, RS[:4], expect={"seq": 0}) == "malformed"


def test_anchors_prove_up_to_themselves() -> None:
    assert export(RS[:4], anchor(3)) == {"first": 1, "last": 4, "proven_to": 3, "status": "prefix", "reason": "unanchored_tail"}
    assert export(RS[:4], anchor(3), anchor(4)) == {"first": 1, "last": 4, "proven_to": 4, "status": "complete", "reason": None}


def test_an_anchor_signed_by_the_executor_is_not_independent() -> None:
    mine = make_seal(key=EXEC, iss=EX, sub=PERSON, executor=EX, seq=4, head_token=RS[3], now=NOW)
    assert code(export, RS[:4], mine, anchor_keys=KEYS) == "anchor_not_independent"


def test_an_anchor_must_match_the_chain() -> None:
    assert code(export, RS[:4], anchor(3, head=RS[3])) == "seal_mismatch"
    assert code(export, RS[:4], anchor(4, executor="https://other.example")) == "seal_mismatch"
    assert code(export, RS[:4], anchor(4, sub="person:2")) == "subject_mismatch"
    assert code(export, RS[:4], anchor(4, key=generate())) == "unknown_key"
    assert code(verify_export, RS[:4], keys=KEYS, executor=EX, anchors=[anchor(4)]) == "malformed"


def test_an_export_that_starts_late_needs_an_anchor_before_it() -> None:
    assert export(RS[2:4], anchor(2), anchor(4)) == {"first": 3, "last": 4, "proven_to": 4, "status": "complete", "reason": None}
    assert export(RS[2:4], anchor(4))["reason"] == "unanchored_start"
    assert export(RS[2:4], anchor(2))["reason"] == "unanchored_tail"
    assert code(export, RS[2:4], anchor(2, head=RS[2]), anchor(4)) == "seal_mismatch"
    assert export(RS[2:4], anchor(1))["proven_to"] is None


def test_route_and_policy_are_optional_receipt_fields() -> None:
    assert verify_chain([receipt(route="task-api", policy=digest({"p": 1}))], keys=KEYS, executor=EX)[0]["route"] == "task-api"
    assert code(receipt, route="") == "malformed"
    assert code(receipt, policy="p1") == "malformed"


def watch(rec: str, effect: str, key=SEER, iss: str = PROVIDER, **kw) -> str:
    return make_observation(key=key, iss=iss, sub=kw.pop("sub", PERSON), executor=kw.pop("executor", EX), receipt_token=rec, effect=effect, now=NOW, **kw)


def judge(rec: str, *obs: str, **kw) -> dict:
    return assess(rec, keys=KEYS, executor=EX, observations=list(obs), observer_keys=kw.pop("observer_keys", SEER_KEYS), **kw)


def a(n: int) -> str:
    return digest({"id": n})


EFFECTS = [  # outcome, observations (effect, subject), effect, verdict
    ("ok", [], "cannot_establish", "cannot_establish"),
    ("ok", [("seen", None)], "observed", "pass"),
    ("ok", [("not_seen", None)], "not_observed", "fail"),
    ("ok", [("not_seen", None), ("seen", None)], "contradicted", "fail"),
    ("unknown", [("not_seen", None), ("seen", None)], "contradicted", "fail"),
    ("ok", [("uncheckable", None)], "cannot_establish", "cannot_establish"),
    ("ok", [("seen", 1), ("seen", 2)], "duplicate", "fail"),
    ("ok", [("seen", 1), ("seen", 1)], "observed", "pass"),
    ("failed", [], "absent", "pass"),
    ("failed", [("not_seen", None)], "absent", "pass"),
    ("failed", [("seen", None)], "contradicted", "fail"),
    ("failed", [("seen", 1), ("seen", 2)], "duplicate", "fail"),
    ("unknown", [], "cannot_establish", "cannot_establish"),
    ("unknown", [("not_seen", None)], "cannot_establish", "cannot_establish"),
    ("unknown", [("seen", None)], "observed", "pass"),
]


@pytest.mark.parametrize("outcome,obs,effect,verdict", EFFECTS)
def test_effect_and_verdict_branches(outcome, obs, effect, verdict) -> None:
    rec = receipt(outcome=outcome)
    got = judge(rec, *[watch(rec, e, **({"subject": a(s)} if s else {})) for e, s in obs])
    assert (got["effect"], got["verdict"], got["decision"], got["route"]) == (effect, verdict, "tier", None)


def test_only_a_reader_other_than_the_executor_counts() -> None:
    rec = receipt()
    mine = watch(rec, "seen", key=EXEC, iss=EX)
    assert code(judge, rec, mine, observer_keys=KEYS) == "observer_not_independent"


def test_an_observation_must_be_about_this_receipt() -> None:
    rec = receipt()
    assert code(judge, rec, watch(receipt(outcome="failed"), "seen")) == "receipt_mismatch"
    assert code(judge, rec, watch(rec, "seen", sub="person:2")) == "subject_mismatch"
    assert code(judge, rec, watch(rec, "seen", executor="https://other.example")) == "executor_mismatch"
    assert code(judge, rec, watch(rec, "seen", key=generate())) == "unknown_key"
    assert code(judge, rec, watch(rec, "seen"), observer_keys=None) == "malformed"


def test_an_unverified_decision_cannot_pass_but_a_missing_effect_still_fails() -> None:
    prev = build_preview(profile={"oac": "0.2", "type": "action-profile", "tool": "add_task", "effect": "write", "undo": {"kind": "native", "window_s": 600},
                                  "tier_floor": "A", "binds": {"title": "title"}}, action=TASK, executor=EX, sub=PERSON, summary="Add", now=NOW)
    cons = make_consent(key=USER, iss=SIGNER, sub=PERSON, aud=EX, previews=[prev], now=NOW, jti="n_consent_0000000001")
    other = make_consent(key=USER, iss=SIGNER, sub=PERSON, aud=EX, previews=[prev], now=NOW, jti="n_consent_0000000002")

    def decided(**authority) -> str:
        return receipt(tier="C", authority={"kind": "consent", "ref": "n_consent_0000000001", "digest": token_digest(cons)} | authority,
                       preview=digest(prev), undo={"kind": "compensate", "until": NOW + 99}, route="task-api")

    rec = decided()
    ok = {"authority_token": cons, "authority_keys": USER_KEYS}
    assert judge(rec, watch(rec, "seen"), **ok) == {"route": "task-api", "decision": "bound", "effect": "observed", "verdict": "pass"}
    assert judge(rec, watch(rec, "seen"))["verdict"] == "cannot_establish"
    assert judge(rec, watch(rec, "not_seen"))["verdict"] == "fail"
    assert judge(rec, **ok)["verdict"] == "cannot_establish"
    assert code(judge, rec, authority_token=other, authority_keys=USER_KEYS) == "authority_mismatch"
    assert code(judge, decided(ref="n_consent_0000000009"), **ok) == "authority_mismatch"
    assert code(judge, rec, authority_token=cons) == "malformed"
    elsewhere = receipt(tier="C", authority={"kind": "consent", "ref": "n_consent_0000000001", "digest": token_digest(cons)},
                        preview=digest({"another": "preview"}), undo={"kind": "compensate", "until": NOW + 99})
    assert code(judge, elsewhere, **ok) == "authority_mismatch"


def row(effect: str, routes: list[str], records: str = "durable") -> dict:
    return {"effect": effect, "key": "k", "held_by": "executor only", "records": records,
            "routes": [{"route": r, "credential": "login", "control": "people only"} for r in routes]}


def tried(effect: str, route: str, occurred: str = "no") -> dict:
    return {"effect": effect, "route": route, "decision": "none", "effect_occurred": occurred, "observed_by": "log"}


@pytest.mark.parametrize("statement,attempts,result,wrong,effects", [
    ([row("e", ["r"])], [tried("e", "x"), tried("e", "r")], "covered", False, {"e": "covered"}),
    ([row("e", ["r"])], [], "not_checked", False, {"e": "not_checked"}),
    ([row("e", ["r"])], [tried("e", "x")], "incomplete", False, {"e": "incomplete"}),
    ([row("e", ["x"])], [tried("e", "x", "cannot_tell")], "incomplete", False, {"e": "incomplete"}),
    ([row("e", ["x"], "memory")], [tried("e", "x")], "incomplete", False, {"e": "incomplete"}),
    ([row("e", ["r"])], [tried("e", "r", "yes")], "bypass", False, {"e": "bypass"}),
    ([row("e", ["r"]), row("f", ["x"])], [tried("e", "r"), tried("e", "z", "yes"), tried("f", "x")], "bypass", True, {"e": "bypass", "f": "covered"}),
    ([row("e", ["x"])], [tried("g", "z", "yes")], "bypass", True, {"e": "not_checked", "g": "bypass"}),
    ([row("e", ["x"]), row("f", ["x"])], [tried("e", "x")], "incomplete", False, {"e": "covered", "f": "not_checked"}),
    ([], [], "not_checked", False, {}),
])
def test_coverage_results(statement, attempts, result, wrong, effects) -> None:
    assert coverage(statement, attempts) == {"result": result, "statement_wrong": wrong, "effects": effects}


def test_coverage_refuses_a_row_without_routes_and_reads_none_as_empty() -> None:
    assert code(coverage, [row("e", [])], []) == "malformed"
    assert coverage(None, None) == {"result": "not_checked", "statement_wrong": False, "effects": {}}
    assert code(coverage, [], {}) == "malformed"
    assert code(coverage, "x", []) == "malformed"


def test_coverage_names_are_ordinary_data() -> None:
    got = coverage([row("__proto__", ["api"])], [tried("__proto__", "api", "yes")])
    assert got == {"result": "bypass", "statement_wrong": False, "effects": {"__proto__": "bypass"}}


def test_coverage_refuses_a_malformed_statement() -> None:
    assert code(coverage, [row("e", ["x"]), row("e", ["x"])], []) == "malformed"
    assert code(coverage, [row("e", ["r", "r"])], []) == "malformed"
    assert code(coverage, [], [{**tried("e", "r"), "effect_occurred": "maybe"}]) == "malformed"


def test_independence_is_by_key_not_only_by_name() -> None:
    renamed = make_seal(key=EXEC, iss="https://notary.example", sub=PERSON, executor=EX, seq=4, head_token=RS[3], now=NOW)
    assert code(export, RS[:4], renamed, anchor_keys=KeySet({"https://notary.example": [EXEC.jwk]})) == "anchor_not_independent"
    rec = receipt()
    assert code(judge, rec, watch(rec, "seen", key=EXEC), observer_keys=KeySet({PROVIDER: [EXEC.jwk]})) == "observer_not_independent"


def test_none_and_wrong_types_are_read_the_same_way_everywhere() -> None:
    rec = receipt()
    assert verify_export(RS[:4], keys=KEYS, executor=EX, anchors=None, anchor_keys=None)["reason"] == "no_anchor"
    assert verify_export(None, keys=KEYS, executor=EX)["first"] is None
    assert code(verify_export, RS[:4], keys=KEYS, executor=EX, anchors="x") == "malformed"
    assert code(verify_export, RS[:4], keys=KEYS, executor=EX, anchors=[5], anchor_keys=USER_KEYS) == "malformed"
    assert code(verify_export, "x", keys=KEYS, executor=EX) == "malformed"
    assert assess(rec, keys=KEYS, executor=EX, observations=None)["verdict"] == "cannot_establish"
    assert code(assess, rec, keys=KEYS, executor=EX, observations="x", observer_keys=SEER_KEYS) == "malformed"
    assert code(assess, rec, keys=KEYS, executor=EX, observations=[5], observer_keys=SEER_KEYS) == "malformed"


def test_an_observation_older_than_its_receipt_shows_the_receipt_time_is_false() -> None:
    rec = receipt(5)  # iat NOW + 5
    old = make_observation(key=SEER, iss=PROVIDER, sub=PERSON, executor=EX, receipt_token=rec, effect="seen", now=NOW + 5 - 61)
    edge = make_observation(key=SEER, iss=PROVIDER, sub=PERSON, executor=EX, receipt_token=rec, effect="seen", now=NOW + 5 - 60)
    assert judge(rec, old)["effect"] == "contradicted"
    assert judge(rec, edge)["effect"] == "observed"


def test_a_future_dated_denial_cannot_hide_an_effect_that_was_seen() -> None:
    # The executor dates a denial an hour ahead so that a real sighting looks stale. In 0.5.0 that passed.
    rec = receipt(1, outcome="failed", iat=NOW + 3600)
    seen = make_observation(key=SEER, iss=PROVIDER, sub=PERSON, executor=EX, receipt_token=rec, effect="seen", now=NOW + 30)
    got = judge(rec, seen)
    assert (got["effect"], got["verdict"]) == ("contradicted", "fail")


def test_the_authority_token_must_be_for_this_person_executor_and_time() -> None:
    import base64

    from oac.jcs import parse
    from oac.jws import sign

    prev = build_preview(profile={"oac": "0.2", "type": "action-profile", "tool": "add_task", "effect": "write", "undo": {"kind": "native", "window_s": 600},
                                  "tier_floor": "A", "binds": {"title": "title"}}, action=TASK, executor=EX, sub=PERSON, summary="Add", now=NOW)
    cons = make_consent(key=USER, iss=SIGNER, sub=PERSON, aud=EX, previews=[prev], now=NOW, jti="n_consent_0000000001")
    body = parse(base64.urlsafe_b64decode(cons.split(".")[1] + "=="))

    def under(token: str) -> str:
        return receipt(tier="C", authority={"kind": "consent", "ref": "n_consent_0000000001", "digest": token_digest(token)},
                       undo={"kind": "compensate", "until": NOW + 99}, preview=digest(prev))

    assert judge(under(cons), authority_token=cons, authority_keys=USER_KEYS)["decision"] == "bound"
    for change in ({"sub": "person:2"}, {"aud": "https://other.example/oac"}, {"iat": NOW + 62, "exp": NOW + 200}):
        moved = sign(body | change, USER, "oac-consent+jws")
        assert code(judge, under(moved), authority_token=moved, authority_keys=USER_KEYS) == "authority_mismatch"


def test_a_mandate_must_be_for_this_person_tool_and_time() -> None:
    from oac import make_mandate

    def mandate(**change) -> str:
        return make_mandate(key=USER, payload={"id": "md_1", "iss": SIGNER, "sub": PERSON, "holder": {"type": "agent", "id": "bot"}, "goal": "g",
                            "tools": ["add_task"], "bounds": {"calls": {"per_day": 5}}, "iat": NOW - 100, "exp": NOW + 100,
                            "signer": {"kind": "custodial"}} | change)

    def under(token: str, **fields) -> str:
        return receipt(tier="C", authority={"kind": "mandate", "ref": "md_1", "digest": token_digest(token)}, **fields)

    good = mandate()
    assert judge(under(good), authority_token=good, authority_keys=USER_KEYS)["decision"] == "bound"
    for token, fields in [(mandate(sub="person:2"), {}), (mandate(tools=["send_email"]), {}), (mandate(exp=NOW), {"iat": NOW + 61}),
                          (mandate(iat=NOW + 100, exp=NOW + 200), {"iat": NOW + 30})]:
        assert code(judge, under(token, **fields), authority_token=token, authority_keys=USER_KEYS) == "authority_mismatch"


def test_an_undo_request_must_be_for_this_person_and_executor() -> None:
    from oac import make_undo

    orig = receipt(tier="B", undo={"kind": "native", "until": NOW + 600, "token": "u1"})

    def request(**kw) -> str:
        return make_undo(key=USER, iss=SIGNER, sub=kw.get("sub", PERSON), aud=kw.get("aud", EX), receipt_token=orig, mode="native", now=NOW,
                         jti="n_undo_00000000000001")

    def under(token: str) -> str:
        return receipt(tier="B", authority={"kind": "undo", "ref": "n_undo_00000000000001", "digest": token_digest(token)}, undoes=token_digest(orig))

    good = request()
    assert judge(under(good), authority_token=good, authority_keys=USER_KEYS)["decision"] == "bound"
    for kw in ({"sub": "person:2"}, {"aud": "https://other.example/oac"}):
        bad = request(**kw)
        assert code(judge, under(bad), authority_token=bad, authority_keys=USER_KEYS) == "authority_mismatch"
