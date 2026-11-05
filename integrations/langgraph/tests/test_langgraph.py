"""End to end through a real LangGraph StateGraph with a checkpointer (pause with interrupt, resume with Command)."""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

from oac import KeySet, generate, make_consent, verify_chain
from oac.gate import Gate
from oac_langgraph import NOT_APPROVED, gated

EX, SIGNER, PERSON = "https://app.example/oac", "https://signer.example", "person:1"


class S(TypedDict, total=False):
    args: dict[str, Any]
    result: Any


def build(tainted: bool = True):
    key = generate()
    gate = Gate(executor=EX, key=generate(), signers=KeySet({SIGNER: [key.jwk]}))
    gate.profile("book_table", effect="write", undo="compensate", window_s=86400,
                 binds={"payee": "restaurant", "when": "time", "count": "party"})
    gate.profile("add_task", effect="write", undo="native", window_s=600, binds={"title": "title"})
    booked: list[Any] = []

    def book_table(restaurant: str, time: str, party: int) -> str:
        booked.append((restaurant, party))
        return "Booked."

    def node(state: S) -> S:
        tool = "add_task" if "title" in state["args"] else "book_table"
        fn = (lambda title: "Added.") if tool == "add_task" else book_table
        return {"result": gated(gate, tool, state["args"], fn, person=PERSON, tainted=tainted)}

    g = StateGraph(S)
    g.add_node("act", node)
    g.add_edge(START, "act")
    g.add_edge("act", END)
    return gate, key, g.compile(checkpointer=InMemorySaver()), booked


ARGS = {"restaurant": "Nobu", "time": "Fri 7:30 pm", "party": 2}


def test_pauses_then_runs_after_a_signed_consent() -> None:
    gate, key, app, booked = build()
    cfg = {"configurable": {"thread_id": "t1"}}
    out = app.invoke({"args": ARGS}, cfg)
    ask = out["__interrupt__"][0].value
    assert ask["oac"] == "consent" and ask["preview"]["fields"] == {"payee": "Nobu", "when": "Fri 7:30 pm", "count": 2} and booked == []
    p = ask["preview"]
    token = make_consent(key=key, iss=SIGNER, sub=PERSON, aud=EX, previews=[p], now=p["iat"] + 1)
    out = app.invoke(Command(resume={"consent": token}), cfg)
    assert out["result"] == "Booked." and booked == [("Nobu", 2)]
    assert verify_chain(gate.receipts[PERSON], keys=KeySet({EX: [gate.key.jwk]}), executor=EX)[0]["authority"]["kind"] == "consent"


def test_resume_without_a_valid_consent_runs_nothing() -> None:
    gate, key, app, booked = build()
    cfg = {"configurable": {"thread_id": "t2"}}
    out = app.invoke({"args": ARGS}, cfg)
    p = out["__interrupt__"][0].value["preview"]
    forged = make_consent(key=generate(), iss=SIGNER, sub=PERSON, aud=EX, previews=[p], now=p["iat"] + 1)
    out = app.invoke(Command(resume={"consent": forged}), cfg)
    assert out["result"] == NOT_APPROVED and booked == []
    out2 = app.invoke({"args": ARGS}, {"configurable": {"thread_id": "t3"}})
    out2 = app.invoke(Command(resume={"approved": True}), {"configurable": {"thread_id": "t3"}})  # a plain yes is not enough
    assert out2["result"] == NOT_APPROVED and booked == []


def test_tier_b_runs_without_pausing_when_not_tainted() -> None:
    gate, key, app, booked = build(tainted=False)
    out = app.invoke({"args": {"title": "Call the dentist"}}, {"configurable": {"thread_id": "t4"}})
    assert out["result"] == "Added." and "__interrupt__" not in out
