"""The framework-neutral Gate: tiers, consent, reuse of a pending preview, receipts."""

from __future__ import annotations

import pytest

from oac import KeySet, OACError, generate, make_consent, verify_chain
from oac.gate import Gate, NeedsConsent

EX, SIGNER, PERSON = "https://app.example/oac", "https://signer.example", "person:1"


def world():
    key = generate()
    gate = Gate(executor=EX, key=generate(), signers=KeySet({SIGNER: [key.jwk]}))
    gate.profile("send_email", effect="send", binds={"to": "to", "title": "subject"}, other_args=["body"])
    gate.profile("add_task", effect="write", undo="native", window_s=600, binds={"title": "title"})
    gate.profile("solve_captcha", effect="write", tier_floor="D")
    return gate, key


def sign(gate, key, preview):
    return gate.accept_consent(make_consent(key=key, iss=SIGNER, sub=PERSON, aud=EX, previews=[preview], now=preview["iat"] + 1))


def test_tier_b_runs_with_receipt_tier_c_needs_consent_then_runs_once() -> None:
    gate, key = world()
    sent: list[str] = []
    gate.run("add_task", {"title": "x"}, lambda title: title, person=PERSON, tainted=False)
    args = {"to": ["sam@example.com"], "subject": "Hi", "body": "Lunch?"}
    with pytest.raises(NeedsConsent) as ask:
        gate.run("send_email", args, lambda **a: sent.append("sent"), person=PERSON)
    again = pytest.raises(NeedsConsent)
    with again as ask2:
        gate.run("send_email", args, lambda **a: sent.append("sent"), person=PERSON)
    assert ask.value.preview == ask2.value.preview  # same pending preview after a re-run
    assert sign(gate, key, ask.value.preview)
    gate.run("send_email", args, lambda **a: sent.append("sent"), person=PERSON)
    assert sent == ["sent"]
    with pytest.raises(NeedsConsent):  # the consent was used once
        gate.run("send_email", args, lambda **a: sent.append("sent"), person=PERSON)
    chain = verify_chain(gate.receipts[PERSON], keys=KeySet({EX: [gate.key.jwk]}), executor=EX)
    assert [r["tier"] for r in chain] == ["B", "C"]


def test_changed_arguments_need_a_new_yes_and_d_never_runs() -> None:
    gate, key = world()
    args = {"to": ["sam@example.com"], "subject": "Hi", "body": "Lunch?"}
    with pytest.raises(NeedsConsent) as ask:
        gate.run("send_email", args, lambda **a: None, person=PERSON)
    sign(gate, key, ask.value.preview)
    with pytest.raises(NeedsConsent):
        gate.run("send_email", {**args, "to": ["boss@evil.test"]}, lambda **a: None, person=PERSON)
    with pytest.raises(OACError) as e:
        gate.run("solve_captcha", {}, lambda: None, person=PERSON)
    assert e.value.code == "tier_d"
    with pytest.raises(OACError) as e2:
        gate.run("send_email", {**args, "bcc": ["x@evil.test"]}, lambda **a: None, person=PERSON)
    assert e2.value.code == "undeclared_argument"


def test_consent_for_another_person_or_executor_is_not_kept() -> None:
    gate, key = world()
    with pytest.raises(NeedsConsent) as ask:
        gate.run("send_email", {"to": ["a@b.co"], "subject": "s"}, lambda **a: None, person=PERSON)
    p = ask.value.preview
    other_aud = make_consent(key=key, iss=SIGNER, sub=PERSON, aud="https://other.example/oac", previews=[p], now=p["iat"] + 1)
    stranger = make_consent(key=generate(), iss=SIGNER, sub=PERSON, aud=EX, previews=[p], now=p["iat"] + 1)
    assert not gate.accept_consent(other_aud) and not gate.accept_consent(stranger) and not gate.accept_consent("junk")
