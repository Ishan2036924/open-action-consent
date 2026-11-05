"""End to end through the official MCP SDK (in-memory client and server, protocol 2026-07-28)."""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("mcp")
from mcp.client import Client
from mcp.client.extension import ClientExtension
from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from mcp_types import ElicitResult

from oac import KeySet, generate, make_consent, verify, verify_chain
from oac.mcp import ID, PREVIEW_KEY, RECEIPT_KEY, OACExtension

EXECUTOR, SIGNER, PERSON = "https://tables.example/oac", "https://signer.example", "person:1"
pytestmark = pytest.mark.anyio


class SpeaksOAC(ClientExtension):
    identifier = ID


def build(person_key: Any, *, tainted: bool = False) -> tuple[MCPServer, OACExtension, list[str]]:
    oac = OACExtension(executor=EXECUTOR, key=generate(), signers=KeySet({SIGNER: [person_key.jwk]}),
                       consent_url=lambda p: f"https://signer.example/consent?r={p['id']}", person=lambda ctx: PERSON,
                       tainted=lambda ctx: tainted)
    server = MCPServer("tables", extensions=[oac])
    log: list[str] = []

    @server.tool(meta=oac.profile("book_table", effect="write", undo="compensate", window_s=86400,
                                  binds={"payee": "restaurant", "when": "time", "count": "party"}))
    async def book_table(restaurant: str, time: str, party: int) -> str:
        log.append(f"booked {restaurant} {party}")
        return "Booked. Confirmation NB-2231."

    @server.tool(meta=oac.profile("add_task", effect="write", undo="native", window_s=600, binds={"title": "title"}))
    async def add_task(title: str) -> str:
        log.append(f"task {title}")
        return "Added."

    @server.tool()
    async def no_profile() -> str:
        log.append("ran")
        return "should never run"

    return server, oac, log


def approver(oac: OACExtension, person_key: Any, *, approve: bool = True, seen: list[dict] | None = None):
    """Plays the person's signer page: shows the preview, signs, posts the Consent to the executor."""

    async def callback(context: Any, params: Any) -> ElicitResult:
        preview = oac.preview(params.url.rsplit("=", 1)[1])
        if seen is not None:
            seen.append(preview)
        if approve:
            oac.accept_consent(make_consent(key=person_key, iss=SIGNER, sub=PERSON, aud=EXECUTOR, previews=[preview],
                                            now=preview["iat"] + 1))
        return ElicitResult(action="accept" if approve else "decline")

    return callback


async def test_tier_c_asks_then_runs_with_a_signed_receipt() -> None:
    key = generate()
    server, oac, log = build(key)
    seen: list[dict] = []
    async with Client(server, extensions=[SpeaksOAC()], elicitation_callback=approver(oac, key, seen=seen)) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        assert tools["book_table"].meta["com.atlasiw/oac-profile"]["effect"] == "write"
        r = await c.call_tool("book_table", {"restaurant": "Nobu", "time": "Fri 7:30 pm", "party": 2})
    assert not r.is_error and log == ["booked Nobu 2"]
    assert seen[0]["fields"] == {"payee": "Nobu", "when": "Fri 7:30 pm", "count": 2}
    receipt = r.meta[RECEIPT_KEY]
    assert verify(receipt, KeySet({EXECUTOR: [oac.key.jwk]}), "oac-receipt+jws")["authority"]["kind"] == "consent"


async def test_declined_means_nothing_runs() -> None:
    key = generate()
    server, oac, log = build(key)
    async with Client(server, extensions=[SpeaksOAC()], elicitation_callback=approver(oac, key, approve=False)) as c:
        r = await c.call_tool("book_table", {"restaurant": "Nobu", "time": "Fri", "party": 2})
    assert r.is_error and log == []


async def test_changed_arguments_on_the_retry_are_refused() -> None:
    key = generate()
    server, oac, log = build(key)
    async with Client(server, extensions=[SpeaksOAC()], elicitation_callback=approver(oac, key)) as c:
        first = await c.session.call_tool("book_table", {"restaurant": "Nobu", "time": "Fri", "party": 2}, allow_input_required=True)
        preview = first.meta[PREVIEW_KEY]
        oac.accept_consent(make_consent(key=key, iss=SIGNER, sub=PERSON, aud=EXECUTOR, previews=[preview], now=preview["iat"] + 1))
        try:
            r = await c.session.call_tool("book_table", {"restaurant": "Nobu", "time": "Fri", "party": 20},
                                          input_responses={"oac_consent": ElicitResult(action="accept")},
                                          request_state=first.request_state, allow_input_required=True)
            refused = r.is_error
        except MCPError:
            refused = True  # the SDK's own request-state binding may refuse first
    assert refused and log == []


async def test_tier_b_runs_at_once_with_undo_token_and_chain() -> None:
    key = generate()
    server, oac, log = build(key)
    async with Client(server, extensions=[SpeaksOAC()]) as c:
        r1 = await c.call_tool("add_task", {"title": "Call the dentist"})
        r2 = await c.call_tool("add_task", {"title": "Buy milk"})
    assert log == ["task Call the dentist", "task Buy milk"]
    chain = verify_chain([r1.meta[RECEIPT_KEY], r2.meta[RECEIPT_KEY]], keys=KeySet({EXECUTOR: [oac.key.jwk]}), executor=EXECUTOR)
    assert chain[0]["undo"]["kind"] == "native" and "token" in chain[0]["undo"]


async def test_tainted_run_raises_tier_b_to_ask() -> None:
    key = generate()
    server, oac, log = build(key, tainted=True)
    async with Client(server, extensions=[SpeaksOAC()], elicitation_callback=approver(oac, key, approve=False)) as c:
        r = await c.call_tool("add_task", {"title": "Wire $500"})
    assert r.is_error and log == []


async def test_tool_without_profile_and_undeclared_argument_never_run() -> None:
    key = generate()
    server, oac, log = build(key)
    async with Client(server, extensions=[SpeaksOAC()]) as c:
        r1 = await c.call_tool("no_profile", {})
        r2 = await c.call_tool("add_task", {"title": "x", "bcc": "boss@evil.test"})
    assert r1.is_error and r2.is_error and log == []


async def test_client_without_the_extension_gets_32021() -> None:
    key = generate()
    server, oac, log = build(key)
    async with Client(server) as c:
        with pytest.raises(MCPError) as e:
            await c.call_tool("book_table", {"restaurant": "Nobu", "time": "Fri", "party": 2})
    assert e.value.error.code == -32021 and log == []


async def test_a_tool_error_with_an_occurrence_blocks_a_repeat_until_resolved() -> None:
    key = generate()
    server, oac, log = build(key)
    answers = iter(["timeout", "ok", "ok"])

    @server.tool(meta=oac.profile("hold_slot", effect="write", undo="native", window_s=600, other_args=["slot"],
                                  occurrence="slot"))
    async def hold_slot(slot: str) -> str:
        if next(answers) == "timeout":
            raise RuntimeError("the provider did not answer")
        log.append(f"held {slot}")
        return "Held."

    async with Client(server, extensions=[SpeaksOAC()]) as c:
        first = await c.call_tool("hold_slot", {"slot": "s_1"})
        blocked = await c.call_tool("hold_slot", {"slot": "s_1"})
        oac.resolve("hold_slot", "s_1", person=PERSON, outcome="failed")
        retried = await c.call_tool("hold_slot", {"slot": "s_1"})
        again = await c.call_tool("hold_slot", {"slot": "s_1"})
    assert first.is_error and blocked.is_error and "occurrence_unresolved" in blocked.content[0].text
    assert not retried.is_error and log == ["held s_1"]
    assert again.is_error and "duplicate_occurrence" in again.content[0].text
    chain = verify_chain(oac.receipts[PERSON], keys=KeySet({EXECUTOR: [oac.key.jwk]}), executor=EXECUTOR)
    assert [r["outcome"] for r in chain] == ["unknown", "ok"]
