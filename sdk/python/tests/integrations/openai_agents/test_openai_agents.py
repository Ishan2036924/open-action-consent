"""End to end through the OpenAI Agents SDK Runner with a fake model (no API key, no network)."""

from __future__ import annotations

import json
from typing import Any

import pytest

pytest.importorskip("agents")
from agents import Agent, ModelSettings, Runner
from agents.models.interface import Model
from agents.items import ModelResponse
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from oac import KeySet, generate, make_consent, verify_chain
from oac.gate import Gate
from oac.openai_agents import NOT_APPROVED, approve, oac_tool, preview_for

EX, SIGNER, PERSON = "https://app.example/oac", "https://signer.example", "person:1"
pytestmark = pytest.mark.anyio


class ScriptedModel(Model):
    """Calls one tool with fixed arguments, then answers with the tool's output."""

    def __init__(self, tool: str, args: dict[str, Any]) -> None:
        self.tool, self.args = tool, args

    async def get_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs, tracing, **kw):
        outputs = [i for i in (input if isinstance(input, list) else []) if isinstance(i, dict) and i.get("type") == "function_call_output"]
        if outputs:
            text = str(outputs[-1].get("output"))
            out = [ResponseOutputMessage(id="m1", role="assistant", status="completed", type="message",
                                         content=[ResponseOutputText(text=text, type="output_text", annotations=[])])]
        else:
            out = [ResponseFunctionToolCall(arguments=json.dumps(self.args), call_id="c1", name=self.tool, type="function_call", id="f1",
                                            status="completed")]
        return ModelResponse(output=out, usage=Usage(), response_id=None)

    def stream_response(self, *a, **k):
        raise NotImplementedError


def world(tool_args: dict[str, Any], *, tainted: bool = True):
    key = generate()
    gate = Gate(executor=EX, key=generate(), signers=KeySet({SIGNER: [key.jwk]}))
    sent: list[dict] = []

    async def send_email(to: list[str], subject: str, body: str = "") -> str:
        """Send an email."""
        sent.append({"to": to, "subject": subject})
        return "sent"

    tool = oac_tool(gate, send_email, person=lambda ctx: PERSON, tainted=lambda ctx: tainted, effect="send",
                    binds={"to": "to", "title": "subject"}, other_args=["body"])
    agent = Agent(name="assistant", tools=[tool], model=ScriptedModel("send_email", tool_args), model_settings=ModelSettings())
    return gate, key, agent, sent


ARGS = {"to": ["sam@example.com"], "subject": "Lunch?", "body": "Friday 1 pm?"}


async def test_pauses_for_tier_c_then_runs_with_a_signed_consent() -> None:
    gate, key, agent, sent = world(ARGS)
    result = await Runner.run(agent, "email Sam")
    assert len(result.interruptions) == 1 and sent == []
    item = result.interruptions[0]
    p = preview_for(gate, item, agent.tools[0], person=PERSON)
    assert p["fields"] == {"to": ["sam@example.com"], "title": "Lunch?"} and p["details"] == {"body": "Friday 1 pm?"}
    state = result.to_state()
    assert approve(gate, state, item, make_consent(key=key, iss=SIGNER, sub=PERSON, aud=EX, previews=[p], now=p["iat"] + 1))
    result = await Runner.run(agent, state)
    assert sent == [{"to": ["sam@example.com"], "subject": "Lunch?"}] and result.final_output == "sent"
    assert verify_chain(gate.receipts[PERSON], keys=KeySet({EX: [gate.key.jwk]}), executor=EX)[0]["tier"] == "C"


async def test_sdk_approval_without_a_signed_consent_runs_nothing() -> None:
    gate, key, agent, sent = world(ARGS)
    result = await Runner.run(agent, "email Sam")
    state = result.to_state()
    state.approve(result.interruptions[0])  # the SDK's own unsigned approval only
    result = await Runner.run(agent, state)
    assert sent == [] and result.final_output == NOT_APPROVED


async def test_a_forged_consent_is_not_accepted() -> None:
    gate, key, agent, sent = world(ARGS)
    result = await Runner.run(agent, "email Sam")
    item = result.interruptions[0]
    p = preview_for(gate, item, agent.tools[0], person=PERSON)
    state = result.to_state()
    assert not approve(gate, state, item, make_consent(key=generate(), iss=SIGNER, sub=PERSON, aud=EX, previews=[p], now=p["iat"] + 1))


async def test_an_extra_argument_never_reaches_the_tool_or_the_preview() -> None:
    """The SDK drops an argument the function does not take before OAC sees it."""
    gate, key, agent, sent = world({**ARGS, "bcc": ["boss@evil.test"]})
    result = await Runner.run(agent, "email Sam")
    p = preview_for(gate, result.interruptions[0], agent.tools[0], person=PERSON)
    assert sent == [] and "bcc" not in json.dumps(p) and "boss@evil.test" not in json.dumps(p)
