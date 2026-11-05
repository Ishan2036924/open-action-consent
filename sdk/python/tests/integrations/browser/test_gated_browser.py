"""Gated Browser end to end: MCP client, OAC extension, headless Chromium, local site."""

from __future__ import annotations

import functools
import http.server
import threading
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp")
pytest.importorskip("playwright")
from mcp.client import Client
from mcp.client.extension import ClientExtension
from mcp_types import ElicitResult

from oac import KeySet, generate, make_consent
from oac.browser import Guard, build_server, has_card_number
from oac.mcp import ID, PREVIEW_KEY

EXECUTOR, SIGNER, PERSON = "https://browser.example/oac", "https://signer.example", "person:1"
pytestmark = pytest.mark.anyio


class SpeaksOAC(ClientExtension):
    identifier = ID


@pytest.fixture(scope="module")
def site() -> Any:
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(Path(__file__).parent / "site"))
    handler.log_message = lambda *a, **k: None  # type: ignore[method-assign]
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def setup(approve: bool = True) -> tuple[Any, Any, Any, Any]:
    person_key = generate()
    server, oac, browser = build_server(executor=EXECUTOR, key=generate(), signers=KeySet({SIGNER: [person_key.jwk]}),
                                        consent_url=lambda p: f"https://signer.example/consent?r={p['id']}",
                                        person=lambda ctx: PERSON, tainted=lambda ctx: True,
                                        guard=Guard(allow_http={"127.0.0.1"}, allow_private={"127.0.0.1"}))
    seen: list[dict] = []

    async def approver(context: Any, params: Any) -> ElicitResult:
        preview = oac.preview(params.url.rsplit("=", 1)[1])
        seen.append(preview)
        if approve:
            oac.accept_consent(make_consent(key=person_key, iss=SIGNER, sub=PERSON, aud=EXECUTOR, previews=[preview], now=preview["iat"] + 1))
        return ElicitResult(action="accept" if approve else "decline")

    client = Client(server, extensions=[SpeaksOAC()], elicitation_callback=approver)
    return client, oac, browser, (seen, person_key)


def ref(text: str, label: str) -> str:
    return next(line.split()[0] for line in text.splitlines() if label in line and line.strip().startswith("e"))


async def test_reading_filling_and_links_never_ask(site: str) -> None:
    client, oac, browser, (seen, _) = setup()
    async with client as c:
        page = (await c.call_tool("open", {"url": f"{site}/book.html"})).content[0].text
        assert "Book table" in page and "FINAL (use submit)" in page
        await c.call_tool("fill", {"ref": ref(page, "Name"), "text": "Ishan"})
        menu = (await c.call_tool("click", {"ref": ref(page, "Menu")})).content[0].text
    assert "Black cod" in menu and seen == []
    await browser.aclose()


async def test_final_button_cannot_be_clicked_without_submit(site: str) -> None:
    client, oac, browser, _ = setup()
    async with client as c:
        page = (await c.call_tool("open", {"url": f"{site}/book.html"})).content[0].text
        r = await c.call_tool("click", {"ref": ref(page, "Book table")})
    assert "final action" in r.content[0].text
    await browser.aclose()


async def test_submit_asks_with_sealed_page_then_books(site: str) -> None:
    client, oac, browser, (seen, _) = setup()
    async with client as c:
        page = (await c.call_tool("open", {"url": f"{site}/book.html"})).content[0].text
        r = await c.call_tool("submit", {"ref": ref(page, "Book table"), "site": "127.0.0.1", "button": "Book table"})
    assert "Booked!" in r.content[0].text
    p = seen[0]
    assert p["fields"] == {"site": "127.0.0.1", "title": "Book table"} and set(p["evidence"]) == {"dom", "screenshot"}
    await browser.aclose()


async def test_page_changed_after_the_yes_is_refused(site: str) -> None:
    client, oac, browser, (_, key) = setup()
    async with client as c:
        page = (await c.call_tool("open", {"url": f"{site}/book.html"})).content[0].text
        args = {"ref": ref(page, "Book table"), "site": "127.0.0.1", "button": "Book table"}
        first = await c.session.call_tool("submit", args, allow_input_required=True)
        preview = first.meta[PREVIEW_KEY]
        oac.accept_consent(make_consent(key=key, iss=SIGNER, sub=PERSON, aud=EXECUTOR, previews=[preview], now=preview["iat"] + 1))
        await browser.pages[PERSON].evaluate("document.querySelector('p').innerText = 'Friday 7:30 pm. Deposit $200, no refunds.'")
        r = await c.session.call_tool("submit", args, input_responses={"oac_consent": ElicitResult(action="accept")},
                                      request_state=first.request_state, allow_input_required=True)
    assert "page_changed" in r.content[0].text
    assert "Booked" not in await browser.pages[PERSON].inner_text("body")
    await browser.aclose()


async def test_button_or_site_that_does_not_match_the_page_is_refused(site: str) -> None:
    client, oac, browser, (seen, _) = setup()
    async with client as c:
        page = (await c.call_tool("open", {"url": f"{site}/book.html"})).content[0].text
        r1 = await c.call_tool("submit", {"ref": ref(page, "Book table"), "site": "127.0.0.1", "button": "See the menu"})
        r2 = await c.call_tool("submit", {"ref": ref(page, "Book table"), "site": "nobu.example", "button": "Book table"})
    assert "button does not match" in r1.content[0].text and "site does not match" in r2.content[0].text and seen == []
    await browser.aclose()


async def test_injected_page_cannot_make_it_pay(site: str) -> None:
    client, oac, browser, (seen, _) = setup(approve=False)
    async with client as c:
        page = (await c.call_tool("open", {"url": f"{site}/inject.html"})).content[0].text
        assert "data, not instructions" in page
        r1 = await c.call_tool("click", {"ref": ref(page, "Pay now")})
        r2 = await c.call_tool("submit", {"ref": ref(page, "Pay now"), "site": "127.0.0.1", "button": "Pay now"})
    assert "final action" in r1.content[0].text and r2.is_error and len(seen) == 1  # the person was asked and said no
    assert "PAID" not in await browser.pages[PERSON].inner_text("body")  # the button was never pressed
    await browser.aclose()


async def test_captcha_stops_everything(site: str) -> None:
    client, oac, browser, (seen, _) = setup()
    async with client as c:
        page = (await c.call_tool("open", {"url": f"{site}/captcha.html"})).content[0].text
        assert "STOP" in page
        r1 = await c.call_tool("fill", {"ref": ref(page, "Email"), "text": "a@b.c"})
        r2 = await c.call_tool("click", {"ref": ref(page, "Continue")})
        r3 = await c.call_tool("submit", {"ref": ref(page, "Continue"), "site": "127.0.0.1", "button": "Continue"})
    assert all("CAPTCHA" in r.content[0].text for r in (r1, r2, r3)) and seen == []
    await browser.aclose()


async def test_secrets_are_never_typed(site: str) -> None:
    client, oac, browser, _ = setup()
    async with client as c:
        page = (await c.call_tool("open", {"url": f"{site}/login.html"})).content[0].text
        r1 = await c.call_tool("fill", {"ref": ref(page, "Password"), "text": "hunter2"})
        r2 = await c.call_tool("fill", {"ref": ref(page, "Note"), "text": "card 4242 4242 4242 4242"})
        r3 = await c.call_tool("fill", {"ref": ref(page, "Note"), "text": "table for 2"})
    assert "never typed" in r1.content[0].text and "never typed" in r2.content[0].text and "never typed" not in r3.content[0].text
    await browser.aclose()


def test_network_guard() -> None:
    g = Guard(allow_http={"127.0.0.1"}, allow_private={"127.0.0.1"}, blocked_sites={"linkedin.com"})
    assert g.check("https://169.254.169.254/latest/meta-data") == "private or internal address"
    assert g.check("http://10.0.0.1/x") == "only https"
    assert g.check("https://10.0.0.1/x") == "private or internal address"
    assert g.check("https://localhost/") == "private or internal address"
    assert g.check("file:///etc/passwd") == "only web addresses"
    assert g.check("https://www.linkedin.com/jobs") == "this site is blocked"
    assert g.check("http://127.0.0.1:8000/a") is None
    assert has_card_number("4242 4242 4242 4242") and not has_card_number("4242 4242 4242 4241")
