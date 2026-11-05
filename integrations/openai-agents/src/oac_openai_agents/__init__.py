"""OAC for the OpenAI Agents SDK (`openai-agents` 0.24+).

The SDK can pause a tool for approval (`needs_approval`) and resume after `state.approve(item)`, but that approval is
an unsigned flag. `oac_tool` adds OAC on top: the pause happens exactly for tier C (computed by OAC, not the model),
the person signs a Consent over the Preview, and the tool body runs only if that Consent verifies for these exact
arguments. Without it, even an approved run refuses. Every run appends a signed receipt.

    gate = Gate(executor=..., key=..., signers=...)
    send = oac_tool(gate, send_email, person=lambda ctx: ctx.context.user_id, effect="send",
                    binds={"to": "to", "title": "subject"}, other_args=["body"])
    agent = Agent(name="assistant", tools=[send])
    result = await Runner.run(agent, "Email Sam")
    for item in result.interruptions:
        p = preview_for(gate, item, person="person:1")   # show it; the person's signer signs a Consent
        state = result.to_state(); approve(gate, state, item, consent_token)
        result = await Runner.run(agent, state)
"""

from __future__ import annotations

import functools
import inspect
import json
from collections.abc import Callable
from typing import Any

from agents import RunContextWrapper, function_tool
from agents.items import ToolApprovalItem
from agents.run_state import RunState

from oac import OACError
from oac.gate import Gate, NeedsConsent

NOT_APPROVED = "Not approved: the person has not signed a consent for exactly this action. Nothing ran."


def _full_args(sig: inspect.Signature, args: dict[str, Any]) -> dict[str, Any]:
    """The same argument dict on both sides (preview and real call): the model's arguments plus the function's
    defaults, so a default the SDK fills in cannot make the action differ from what the person approved."""
    bound = sig.bind_partial(**args)
    bound.apply_defaults()
    return dict(bound.arguments)


def oac_tool(gate: Gate, fn: Callable[..., Any], *, person: Callable[[RunContextWrapper[Any]], str],
             tainted: Callable[[RunContextWrapper[Any]], bool] | None = None, name: str | None = None, **profile: Any) -> Any:
    tool_name = name or fn.__name__
    gate.profile(tool_name, **profile)
    is_tainted = tainted or (lambda ctx: True)  # spec section 4: unknown = tainted
    sig = inspect.signature(fn)

    async def needs_approval(ctx: RunContextWrapper[Any], args: dict[str, Any], call_id: str) -> bool:
        try:
            full = _full_args(sig, args)
            if gate.tier(tool_name, full, tainted=is_tainted(ctx)) != "C":
                return False
        except (OACError, TypeError):
            return False  # the body refuses it with the reason
        gate.preview(tool_name, full, person=person(ctx))
        return True

    @functools.wraps(fn)
    async def body(ctx: RunContextWrapper[Any], *pos: Any, **kw: Any) -> Any:
        try:
            args = _full_args(sig, dict(sig.bind(*pos, **kw).arguments))
            result, _receipt = await gate.arun(tool_name, args, fn, person=person(ctx), tainted=is_tainted(ctx))
        except NeedsConsent:
            return NOT_APPROVED
        except OACError as e:
            return f"Refused ({e.code}). Nothing ran."
        except TypeError:
            return "Refused (malformed arguments). Nothing ran."
        return result

    ctx_param = inspect.Parameter("ctx", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=RunContextWrapper[Any])
    body.__signature__ = sig.replace(parameters=[ctx_param, *sig.parameters.values()])  # type: ignore[attr-defined]
    body.__annotations__ = {"ctx": RunContextWrapper[Any], **getattr(fn, "__annotations__", {})}
    tool = function_tool(body, name_override=tool_name, needs_approval=needs_approval)
    tool._oac_signature = sig  # type: ignore[attr-defined]
    return tool


def preview_for(gate: Gate, item: ToolApprovalItem, tool: Any, *, person: str) -> dict[str, Any]:
    """The Preview to show for an interruption (the same one `needs_approval` registered). `tool` is the object
    `oac_tool` returned."""
    raw = json.loads(getattr(item.raw_item, "arguments", "{}") or "{}")
    sig = tool._oac_signature
    # The SDK validates arguments against the function's parameters and drops any other (a hidden "bcc") before
    # needs_approval and the tool see them; mirror that so the Preview is the call that will run. If an SDK ever
    # passed an extra argument through, the call would not match this Preview and would be refused.
    args = {k: v for k, v in raw.items() if k in sig.parameters}
    return gate.preview(tool.name, _full_args(sig, args), person=person)


def approve(gate: Gate, state: RunState[Any, Any], item: ToolApprovalItem, consent_token: str) -> bool:
    """Hand the signed Consent to the gate and let the run continue. Returns False (and does not approve) when the
    Consent is not valid for a pending Preview."""
    if not gate.accept_consent(consent_token):
        return False
    state.approve(item)
    return True
