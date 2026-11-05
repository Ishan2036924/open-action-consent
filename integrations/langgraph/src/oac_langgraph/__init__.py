"""OAC for LangGraph (1.2+). Use `gated` inside any node that acts for a person:

    def book(state):
        result = gated(gate, "book_table", state["args"], book_table, person=state["person"], tainted=state["tainted"])
        return {"result": result}

Tier A/B run at once (B with a receipt). Tier C pauses the graph with LangGraph's `interrupt`, carrying the OAC
Preview: `{"oac": "consent", "preview": {...}}`. Resume with `Command(resume={"consent": "<signed JWS>"})`; the action
runs only if that Consent verifies for exactly this action, otherwise the node returns NOT_APPROVED and nothing runs.
LangGraph re-runs the node from the top on resume; the Gate reuses the pending Preview, so the person's signature
still matches.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from langgraph.types import interrupt

from oac import OACError
from oac.gate import Gate, NeedsConsent

NOT_APPROVED = "Not approved: the person did not sign a consent for exactly this action. Nothing ran."


def gated(gate: Gate, tool: str, args: Mapping[str, Any], fn: Callable[..., Any], *, person: str, tainted: bool = True) -> Any:
    try:
        return gate.run(tool, args, fn, person=person, tainted=tainted)[0]
    except NeedsConsent as ask:
        answer = interrupt({"oac": "consent", "preview": ask.preview})
    except OACError as e:
        return f"Refused ({e.code}). Nothing ran."
    token = answer.get("consent") if isinstance(answer, Mapping) else None
    if not isinstance(token, str) or not gate.accept_consent(token):
        return NOT_APPROVED
    try:
        return gate.run(tool, args, fn, person=person, tainted=tainted)[0]
    except (NeedsConsent, OACError):
        return NOT_APPROVED
