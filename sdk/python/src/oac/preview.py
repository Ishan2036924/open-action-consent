"""Actions and Previews (spec sections 3 and 5). An action is {tool, args}; a Preview is what the executor shows the
person before a yes. Every argument is declared by the tool's Action Profile: a bound one appears as a checked field,
any other one appears unchanged in `details`. So everything that will run is something the person was shown."""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from typing import Any

from oac import shapes
from oac.errors import OACError
from oac.jcs import canonical
from oac.jws import digest


def action_digest(action: Mapping[str, Any]) -> str:
    a = shapes.action(dict(action))
    return digest({"tool": a["tool"], "args": a["args"]})


def build_preview(
    *,
    profile: Mapping[str, Any],
    action: Mapping[str, Any],
    executor: str,
    sub: str,
    summary: str,
    now: int,
    ttl: int = 600,
    preview_id: str | None = None,
    cancel_policy: Mapping[str, Any] | None = None,
    evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    shapes.profile(profile)
    if action["tool"] != profile["tool"]:
        raise OACError("unknown_tool", "action and profile name different tools")
    shapes.check_action(action, profile)
    args = action["args"]
    fields = {f: args[a] for f, a in profile.get("binds", {}).items() if a in args}
    details = {a: args[a] for a in profile.get("other_args", []) if a in args}
    doc: dict[str, Any] = {
        "oac": shapes.VERSION,
        "type": "preview",
        "id": preview_id or "pv_" + secrets.token_urlsafe(12),
        "executor": executor,
        "sub": sub,
        "tool": action["tool"],
        "action": action_digest(action),
        "summary": summary,
        "fields": fields,
        "undo": dict(profile["undo"]),
        **({"details": details} if details else {}),
        "iat": now,
        "exp": now + ttl,
    }
    if cancel_policy is not None:
        doc["cancel_policy"] = dict(cancel_policy)
    if evidence is not None:
        doc["evidence"] = dict(evidence)
    return shapes.preview(doc)


def check_binding(preview: Mapping[str, Any], action: Mapping[str, Any], profile: Mapping[str, Any]) -> None:
    """Raise unless the action is one the profile declares (undeclared_argument / malformed) and every Preview field
    and detail equals its argument and the undo shown is the profile's own (binding_mismatch)."""
    shapes.check_action(action, profile)
    binds: Mapping[str, str] = profile.get("binds", {})
    fields: Mapping[str, Any] = preview["fields"]
    for f in fields:
        if f not in binds:
            raise OACError("binding_mismatch", f"field {f} is not bound to an argument")
    for f, arg in binds.items():
        has_field, has_arg = f in fields, arg in action["args"]
        if has_field != has_arg or (has_field and canonical(fields[f]) != canonical(action["args"][arg])):
            raise OACError("binding_mismatch", f"field {f} does not match argument {arg}")
    others = {a: action["args"][a] for a in profile.get("other_args", []) if a in action["args"]}
    if canonical(preview.get("details", {})) != canonical(others):
        raise OACError("binding_mismatch", "details differ from the other arguments")
    if preview["tool"] != action["tool"] or canonical(preview["undo"]) != canonical(profile["undo"]):
        raise OACError("binding_mismatch", "tool or undo differs from the profile")
