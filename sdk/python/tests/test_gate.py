"""The framework-neutral Gate: tiers, consent, reuse of a pending preview, receipts."""

from __future__ import annotations

import asyncio

import pytest

from oac import DeviceCheck, KeySet, MemoryOccurrences, OACError, generate, make_consent, token_digest, verify_chain
from oac.gate import ActionFailed, Gate, NeedsConsent
from oac.jcs import parse
from oac.jws import b64url_decode
from oac.testing import passkey_proof

EX, SIGNER, PERSON = "https://app.example/oac", "https://signer.example", "person:1"


def world():
    key = generate()
    gate = Gate(executor=EX, key=generate(), signers=KeySet({SIGNER: [key.jwk]}))
    gate.profile("send_email", effect="send", binds={"to": "to", "title": "subject"}, other_args=["body"])
    gate.profile("add_task", effect="write", undo="native", window_s=600, binds={"title": "title"})
    gate.profile("solve_captcha", effect="write", tier_floor="D")
    return gate, key


def payload_jti(token: str) -> str:
    return parse(b64url_decode(token.split(".")[1]))["jti"]


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


def pay_world():
    gate, key = world()
    gate.profile("pay_order", effect="pay", undo="compensate", window_s=86400, other_args=["order"], occurrence="order",
                 binds={"amount_minor": "amount", "currency": "currency", "payee": "shop"})
    return gate, key


PAY = {"amount": 1800, "currency": "USD", "shop": "Sweetgreen", "order": "ord_1"}


def approve_payment(gate, key) -> None:
    with pytest.raises(NeedsConsent) as ask:
        gate.run("pay_order", PAY, lambda **a: None, person=PERSON)
    p = ask.value.preview
    pay = {"rail": "stripe_link", "ref": "lsrq_test_1", "amount_minor": 1800, "currency": "USD", "payee": "Sweetgreen"}
    assert gate.accept_consent(make_consent(key=key, iss=SIGNER, sub=PERSON, aud=EX, previews=[p], now=p["iat"] + 1,
                                            payment=pay))


def provider_timeout(**a):
    raise TimeoutError("the provider did not answer")


def code_of(call) -> str:
    with pytest.raises(OACError) as e:
        call()
    return e.value.code


def test_a_timed_out_payment_cannot_be_paid_again_until_resolved() -> None:
    gate, key = pay_world()
    charged: list[str] = []

    def pay(**a):
        charged.append("paid")

    approve_payment(gate, key)
    with pytest.raises(TimeoutError):
        gate.run("pay_order", PAY, provider_timeout, person=PERSON)
    # nobody is asked again while the first attempt's outcome is unknown
    assert code_of(lambda: gate.run("pay_order", PAY, pay, person=PERSON)) == "occurrence_unresolved"

    gate.resolve("pay_order", "ord_1", person=PERSON, outcome="failed")  # the provider says nothing was charged
    approve_payment(gate, key)
    gate.run("pay_order", PAY, pay, person=PERSON)
    assert code_of(lambda: gate.run("pay_order", PAY, pay, person=PERSON)) == "duplicate_occurrence"
    assert charged == ["paid"]

    chain = verify_chain(gate.receipts[PERSON], keys=KeySet({EX: [gate.key.jwk]}), executor=EX)
    assert [r["outcome"] for r in chain] == ["unknown", "ok"]
    assert all(r["occurrence"] == "ord_1" for r in chain)


def test_a_yes_held_while_the_first_attempt_is_unclear_is_not_used_up() -> None:
    gate, key = pay_world()
    approve_payment(gate, key)
    with pytest.raises(TimeoutError):
        gate.run("pay_order", PAY, provider_timeout, person=PERSON)
    gate.resolve("pay_order", "ord_1", person=PERSON, outcome="failed")
    approve_payment(gate, key)
    gate.occurrences.finish((PERSON, "tool:pay_order", "ord_1"), "unknown")  # another worker's attempt is unclear
    assert code_of(lambda: gate.run("pay_order", PAY, lambda **a: None, person=PERSON)) == "occurrence_unresolved"
    gate.resolve("pay_order", "ord_1", person=PERSON, outcome="failed")
    gate.run("pay_order", PAY, lambda **a: None, person=PERSON)  # the held yes still works


def test_a_cancelled_payment_is_recorded_as_unknown_and_can_be_resolved() -> None:
    gate, key = pay_world()
    approve_payment(gate, key)

    async def slow(**a):
        await asyncio.sleep(10)

    async def go():
        await asyncio.wait_for(gate.arun("pay_order", PAY, slow, person=PERSON), 0.01)

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(go())
    assert gate.occurrences.state((PERSON, "tool:pay_order", "ord_1")) == "unknown"
    (r,) = verify_chain(gate.receipts[PERSON], keys=KeySet({EX: [gate.key.jwk]}), executor=EX)
    assert r["outcome"] == "unknown"
    gate.occurrences.finish((PERSON, "tool:pay_order", "ord_1"), "running")  # as if the process had crashed mid-call
    gate.resolve("pay_order", "ord_1", person=PERSON, outcome="ok")
    assert code_of(lambda: gate.run("pay_order", PAY, lambda **a: None, person=PERSON)) == "duplicate_occurrence"


def test_receipts_name_the_exact_consent_token() -> None:
    gate, key = world()
    args = {"to": ["sam@example.com"], "subject": "Hi"}
    with pytest.raises(NeedsConsent) as ask:
        gate.run("send_email", args, lambda **a: None, person=PERSON)
    token = make_consent(key=key, iss=SIGNER, sub=PERSON, aud=EX, previews=[ask.value.preview], now=ask.value.preview["iat"] + 1)
    gate.accept_consent(token)
    _, receipt = gate.run("send_email", args, lambda **a: None, person=PERSON)
    (r,) = verify_chain([receipt], keys=KeySet({EX: [gate.key.jwk]}), executor=EX)
    assert r["authority"] == {"kind": "consent", "ref": payload_jti(token), "digest": token_digest(token)}
    assert gate.tokens[r["authority"]["digest"]] == token


def test_an_error_the_tool_marks_as_failed_allows_a_retry() -> None:
    gate, key = world()
    gate.profile("book", effect="write", undo="native", window_s=600, other_args=["slot"], occurrence="slot")

    def full(**a):
        raise ActionFailed("no table left")

    with pytest.raises(ActionFailed):
        gate.run("book", {"slot": "s_1"}, full, person=PERSON, tainted=False)
    gate.run("book", {"slot": "s_1"}, lambda **a: "booked", person=PERSON, tainted=False)


def test_a_gate_that_needs_a_passkey_runs_only_with_a_proof_over_that_consent() -> None:
    key, passkey = generate(), generate("ES256")
    need = DeviceCheck(None, {"cred-1": passkey.jwk}, "app.example", ["https://app.example"])
    gate = Gate(executor=EX, key=generate(), signers=KeySet({SIGNER: [key.jwk]}),
                device=lambda person, action: need if action["tool"] == "send_email" else None)
    gate.profile("send_email", effect="send", binds={"to": "to", "title": "subject"}, other_args=["body"])
    args = {"to": ["sam@example.com"], "subject": "Hi", "body": "See you at 6"}
    sent: list[str] = []
    with pytest.raises(NeedsConsent) as ask:
        gate.run("send_email", args, lambda **a: sent.append("sent"), person=PERSON)
    p = ask.value.preview
    token = make_consent(key=key, iss=SIGNER, sub=PERSON, aud=EX, previews=[p], now=p["iat"] + 1)
    assert gate.accept_consent(token)
    assert code_of(lambda: gate.run("send_email", args, lambda **a: sent.append("sent"), person=PERSON)) == "device_proof_missing"
    other = make_consent(key=key, iss=SIGNER, sub=PERSON, aud=EX, previews=[p], now=p["iat"] + 2)
    assert not gate.accept_consent(other, proof=passkey_proof(other, passkey))  # never replaces the kept token
    proof = passkey_proof(token, passkey)
    assert gate.accept_consent(token, proof=proof)  # the same token may bring its proof later
    assert gate.accept_consent(token, proof={"junk": 1})  # a junk re-post is not kept, so it cannot block the run
    _, receipt = gate.run("send_email", args, lambda **a: sent.append("sent"), person=PERSON)
    assert sent == ["sent"] and gate.device_proofs[token_digest(token)] == proof


def test_two_pay_tools_with_one_provider_scope_share_an_order() -> None:
    gate, key = world()
    binds = {"amount_minor": "amount", "currency": "currency", "payee": "shop"}
    for tool in ("pay_order", "pay_express"):
        gate.profile(tool, effect="pay", undo="compensate", window_s=86400, other_args=["order"], occurrence="order",
                     occurrence_scope="stripe:acct_1", binds=binds)
    approve_payment(gate, key)
    _, receipt = gate.run("pay_order", PAY, lambda **a: "paid", person=PERSON)
    assert parse(b64url_decode(receipt.split(".")[1]))["occurrence_scope"] == "stripe:acct_1"
    # refused before the person is asked: the order already ran through the other tool
    assert code_of(lambda: gate.run("pay_express", PAY, lambda **a: "paid", person=PERSON)) == "duplicate_occurrence"
    # a tool whose name is spelled like that scope keeps orders of its own
    gate.profile("stripe:acct_1", effect="write", undo="native", window_s=600, other_args=["order"], occurrence="order")
    gate.run("stripe:acct_1", {"order": "ord_1"}, lambda **a: "held", person=PERSON, tainted=False)


def test_a_tool_cannot_move_to_another_order_scope_while_it_has_orders() -> None:
    gate, key = pay_world()
    pay_profile = dict(effect="pay", undo="compensate", window_s=86400, other_args=["order"], occurrence="order",
                       binds={"amount_minor": "amount", "currency": "currency", "payee": "shop"})
    gate.profile("pay_order", **pay_profile, occurrence_scope="stripe:acct_1")  # no orders yet: allowed
    approve_payment(gate, key)
    gate.run("pay_order", PAY, lambda **a: "paid", person=PERSON)
    gate.profile("pay_order", **pay_profile, occurrence_scope="stripe:acct_1")  # the same scope again: allowed
    for other in ("stripe:acct_2", None):
        with pytest.raises(ValueError):
            gate.profile("pay_order", **pay_profile, occurrence_scope=other)
    # the refused change left the profile as it was, so the paid order still cannot run again
    assert code_of(lambda: gate.run("pay_order", PAY, lambda **a: "paid", person=PERSON)) == "duplicate_occurrence"


def test_a_store_that_cannot_list_a_scope_refuses_every_scope_change() -> None:
    class Opaque:  # an occurrence store without has_scope
        def __init__(self):
            self._inner = MemoryOccurrences()

        def __getattr__(self, name):
            if name == "has_scope":
                raise AttributeError(name)
            return getattr(self._inner, name)

    gate = Gate(executor=EX, key=generate(), signers=KeySet({}), occurrences=Opaque())
    gate.profile("pay_order", effect="pay", undo="compensate", window_s=86400, other_args=["order"], occurrence="order",
                 binds={"amount_minor": "amount", "currency": "currency", "payee": "shop"})
    with pytest.raises(ValueError):
        gate.profile("pay_order", effect="pay", undo="compensate", window_s=86400, other_args=["order"],
                     occurrence="order", occurrence_scope="stripe:acct_1",
                     binds={"amount_minor": "amount", "currency": "currency", "payee": "shop"})
