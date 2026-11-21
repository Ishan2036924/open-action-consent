"""Property-based fuzzing of the LiteLLM guardrail's hooks, with everything a caller or the gateway can put in a call.

A hostile call is refused with an HTTP error that names what happened (`oac_refused` with a code, `oac_consent_required`
or `oac_misconfigured`), never another exception; a call that passes is pinned to exactly the arguments checked, and
its outcome event always closes it with a receipt. Seeded; OAC_FUZZ_EXAMPLES raises the budget.
"""

from __future__ import annotations

import asyncio
import copy
import os
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("litellm.proxy.proxy_server")
pytest.importorskip("hypothesis")

from fastapi import HTTPException  # noqa: E402
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from oac import CODES, KeySet, generate, make_consent, verify_chain  # noqa: E402
from oac.gate import Gate  # noqa: E402
from oac.litellm import OACGuardrail  # noqa: E402

EXAMPLES = int(os.environ.get("OAC_FUZZ_EXAMPLES", "100"))
FUZZ = settings(max_examples=EXAMPLES, derandomize=True, deadline=None, database=None,
                suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])

EX, SIGNER, NOW = "https://gateway.example/oac", "https://signer.example", 1_800_000_000
EXEC, SIGNER_KEY = generate(), generate()
PROFILES = {
    "notes/read_note": {"effect": "read", "binds": {"title": "title"}},
    "tasks/add_task": {"effect": "write", "undo": "native", "window_s": 600, "binds": {"title": "title"}},
    "mail/send_email": {"effect": "send", "binds": {"to": "to", "title": "subject"}, "other_args": ["body"]},
    "files/wipe_drive": {"effect": "delete", "tier_floor": "D", "binds": {"title": "drive"}},
    "shop/order": {"effect": "write", "undo": "native", "window_s": 60, "binds": {"title": "item"},
                   "other_args": ["order_id"], "occurrence": "order_id", "occurrence_scope": "shop"},
}
VALID_ARGS = [{"title": "Call"}, {"to": ["pat@example.org"], "subject": "Hi", "body": "x"}, {"item": "tea", "order_id": "o-1"},
              {"drive": "C"}]


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> int:
        return self.now


def build(tainted: bool) -> OACGuardrail:
    clock = Clock()
    gate = Gate(executor=EX, key=EXEC, signers=KeySet({SIGNER: [SIGNER_KEY.jwk]}), clock=clock)
    g = OACGuardrail(guardrail_name="oac", event_hook=["pre_mcp_call"], default_on=True, gate=gate,
                     profiles=PROFILES, tainted=tainted, clock=clock)
    g.test_clock = clock  # type: ignore[attr-defined]
    return g


scalars = st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=12)
json_values = st.recursive(scalars, lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=8), c, max_size=4),
                           max_leaves=12)
names = st.sampled_from(sorted({t.split("/")[0] for t in PROFILES}) + sorted({t.split("/")[1] for t in PROFILES})) | json_values
args = st.sampled_from(VALID_ARGS) | st.dictionaries(st.sampled_from(["title", "to", "subject", "body", "item", "order_id", "drive", "x"])
                                                     | st.text(max_size=5), json_values, max_size=5) | json_values
people = st.sampled_from(["alice", "team-7"]) | json_values | st.text(alphabet=st.characters(codec="utf-8"), max_size=10)


def consent_for(g: OACGuardrail, person: str) -> str:
    """A real Consent for every pending Preview of this person, so the header path can pass too."""
    previews = [p for (who, _), p in g.gate.pending.items() if who == person]
    return make_consent(key=SIGNER_KEY, iss=SIGNER, sub=person, aud=EX, previews=previews[:1], now=NOW) if previews else "x.y.z"


@st.composite
def calls(draw) -> tuple[dict, str]:
    data: dict[str, Any] = {}
    for field, value in (("mcp_server_name", names), ("mcp_tool_name", names), ("mcp_arguments", args),
                         ("modified_arguments", st.none() | args), ("user_api_key_user_id", people)):
        if draw(st.integers(0, 3)):  # mostly present
            data[field] = draw(value)
    if draw(st.booleans()):
        tool = draw(st.sampled_from(sorted(PROFILES)))
        data["mcp_server_name"], data["mcp_tool_name"] = tool.split("/")
    meta = draw(st.sampled_from(["none", "headers", "hostile"]))
    if meta == "headers":
        data["metadata"] = {"headers": draw(st.dictionaries(st.sampled_from(["x-oac-consent", "X-OAC-Consent", "other"]),
                                                            json_values | st.just("CONSENT"), max_size=2)),
                            "user_api_key_user_id": draw(people)}
    elif meta == "hostile":
        data["metadata"] = draw(json_values | st.fixed_dictionaries({"headers": json_values}))
    data["litellm_logging_obj"] = draw(st.sampled_from([None, "x", SimpleNamespace(model_call_details={}, litellm_call_id="c1")]))
    call_type = draw(st.sampled_from(["call_mcp_tool", "call_mcp_tool", "list_mcp_tools", "acompletion"]))
    return data, call_type


def refusal(e: HTTPException) -> None:
    assert e.status_code in (403, 500)
    assert e.detail["error"] in ("oac_refused", "oac_consent_required", "oac_misconfigured")
    if e.detail["error"] == "oac_refused":
        assert e.detail["code"] in CODES


@FUZZ
@given(calls(), st.booleans(), st.booleans())
def test_pre_call_hook_refuses_or_pins(call: tuple[dict, str], tainted: bool, consent_first: bool) -> None:
    data, call_type = call
    g = build(tainted)
    authorized = 0
    if consent_first:  # ask once so a Preview is pending, then answer it in the header
        try:
            asyncio.run(g.async_pre_call_hook(None, None, dict(data), call_type))
            authorized += call_type == "call_mcp_tool"
        except HTTPException:
            pass
        person = data.get("user_api_key_user_id")
        meta = data.get("metadata")
        if isinstance(person, str) and isinstance(meta, dict) and isinstance(meta.get("headers"), dict):
            meta["headers"] = {k: (consent_for(g, f"user_id:{person}") if v == "CONSENT" else v) for k, v in meta["headers"].items()}
    expected = copy.deepcopy(data.get("modified_arguments") or data.get("mcp_arguments") or {})
    try:
        out = asyncio.run(g.async_pre_call_hook(None, None, data, call_type))
    except HTTPException as e:
        refusal(e)
        return
    if call_type != "call_mcp_tool":
        return
    authorized += 1
    assert out["modified_arguments"] == expected  # pinned: the tool runs with exactly what was checked
    # the outcome event closes the attempt with a receipt, whatever LiteLLM reports
    logging_obj = data.get("litellm_logging_obj")
    details = {**getattr(logging_obj, "model_call_details", {}), "call_type": "call_mcp_tool", "litellm_call_id": "c1"}
    asyncio.run(g.async_log_success_event(details, SimpleNamespace(isError=False, content="done"), 0, 1))
    # an attempt the event cannot be matched to (no logging object) is closed as unknown by the sweep after the timeout
    g.test_clock.now += g.ticket_timeout_s
    g._sweep()
    chains = list(g.gate.receipts.values())
    assert sum(len(c) for c in chains) == authorized  # every authorized attempt has exactly one receipt
    for chain in chains:
        assert verify_chain(chain, keys=KeySet({EX: [EXEC.jwk]}), executor=EX)


outcome_kwargs = st.fixed_dictionaries({}, optional={
    "call_type": st.sampled_from(["call_mcp_tool", "acompletion"]) | json_values,
    "oac_ticket": st.sampled_from([[None], {"a": 1}, 7]) | st.text(max_size=6) | json_values,
    "litellm_call_id": st.sampled_from(["c1", "c2"]) | json_values,
    "exception": st.sampled_from([None, ValueError("x"), HTTPException(status_code=429), HTTPException(status_code=502),
                                  SimpleNamespace(status_code="403")]),
})


@FUZZ
@given(outcome_kwargs, st.sampled_from([None, "done", SimpleNamespace(isError=True), SimpleNamespace(is_error="yes")]),
       st.booleans())
def test_outcome_events_never_raise(kwargs: dict, response: Any, success: bool) -> None:
    # events for calls OAC never authorized, or forged fields, change nothing and never fail the gateway's logging
    g = build(False)
    data = {"mcp_server_name": "tasks", "mcp_tool_name": "add_task", "mcp_arguments": {"title": "Call"},
            "user_api_key_user_id": "alice", "litellm_logging_obj": SimpleNamespace(model_call_details={}, litellm_call_id="c1")}
    asyncio.run(g.async_pre_call_hook(None, None, data, "call_mcp_tool"))
    event = g.async_log_success_event if success else g.async_log_failure_event
    asyncio.run(event(kwargs, response, 0, 1))
    assert sum(len(c) for c in g.gate.receipts.values()) <= 1
