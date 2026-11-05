"""OAC for the OpenAI Agents SDK. See guides/openai-agents.md."""

from __future__ import annotations

import functools
import inspect
import json
from collections.abc import Callable, Mapping
from typing import Any

try:
    from agents import RunContextWrapper, function_tool
    from agents.items import ToolApprovalItem
    from agents.run_state import RunState
except ImportError as e:  # the optional dependency is not installed
    raise ImportError('oac.openai_agents needs the OpenAI Agents SDK: pip install "open-action-consent[openai-agents]"') from e

from oac import OACError
from oac.gate import Gate, NeedsConsent

NOT_APPROVED = "Not approved: the person has not signed a consent for exactly this action. Nothing ran."


def _full_args(sig: inspect.Signature, args: dict[str, Any]) -> dict[str, Any]:
    """The model's arguments plus the function's defaults, so both sides see the same call."""
    bound = sig.bind_partial(**args)
    bound.apply_defaults()
    return dict(bound.arguments)


def oac_tool(gate: Gate, fn: Callable[..., Any], *, person: Callable[[RunContextWrapper[Any]], str],
             tainted: Callable[[RunContextWrapper[Any]], bool] | None = None, name: str | None = None, **profile: Any) -> Any:
    tool_name = name or fn.__name__
    gate.profile(tool_name, **profile)
    is_tainted = tainted or (lambda ctx: True)  # unknown means tainted
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
    """The Preview to show the person for this interruption."""
    raw = json.loads(getattr(item.raw_item, "arguments", "{}") or "{}")
    sig = tool._oac_signature
    # the SDK drops arguments the function does not take; do the same so the Preview is the call that runs
    args = {k: v for k, v in raw.items() if k in sig.parameters}
    return gate.preview(tool.name, _full_args(sig, args), person=person)


def approve(gate: Gate, state: RunState[Any, Any], item: ToolApprovalItem, consent_token: str,
            device_proof: Mapping[str, Any] | None = None) -> bool:
    """Hand the Consent (and any passkey proof) to the gate and approve the item. False if the Consent is not valid."""
    if not gate.accept_consent(consent_token, device_proof):
        return False
    state.approve(item)
    return True
