"""OAC for LangGraph: tier C pauses the graph with interrupt. See guides/langgraph.md."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

try:
    from langgraph.types import interrupt
except ImportError as e:  # the optional dependency is not installed
    raise ImportError('oac.langgraph needs LangGraph: pip install "open-action-consent[langgraph]"') from e

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
