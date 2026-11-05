"""The Approver in a real headless Chromium."""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from typing import Any

import pytest

pytest.importorskip("starlette")
pytest.importorskip("playwright")
import uvicorn
from playwright.sync_api import sync_playwright

from oac import KeySet, MemoryNonces, verify, verify_consent
from oac.discovery import keyset_from, metadata_url
from oac.preview import build_preview
from oac.approver import Approver

ISSUER, PERSON, EXECUTOR = "https://approve.example", "person:1", "https://tables.example/oac"
PROFILE = {"oac": "0.2", "type": "action-profile", "tool": "book_table", "effect": "write",
           "undo": {"kind": "compensate", "window_s": 86400}, "tier_floor": "A",
           "binds": {"payee": "restaurant", "when": "time", "count": "party"}, "other_args": ["note"]}


class World:
    def __init__(self) -> None:
        self.previews: dict[str, dict[str, Any]] = {}
        self.delivered: list[str] = []
        self.approver = Approver(issuer=ISSUER, person=PERSON, previews=self.previews.get,
                                 deliver=lambda t: self.delivered.append(t) or True, enrollment_code="code-1234")

    def ask(self, args: dict[str, Any], summary: str) -> tuple[dict[str, Any], dict[str, Any]]:
        action = {"tool": "book_table", "args": args}
        p = build_preview(profile=PROFILE, action=action, executor=EXECUTOR, sub=PERSON, summary=summary, now=int(time.time()),
                          cancel_policy={"text": "Free cancellation until 24 h before."})
        self.previews[p["id"]] = p
        return p, action


@pytest.fixture(scope="module")
def world() -> Any:
    w = World()
    server = uvicorn.Server(uvicorn.Config(w.approver.app(), host="127.0.0.1", port=0, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    while not server.started:
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    w.base = f"http://127.0.0.1:{port}"
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        w.page = browser.new_context().new_page()
        yield w
        browser.close()
    server.should_exit = True


def status(page: Any) -> str:
    """Poll the status line. The page's CSP blocks the eval wait_for_function needs."""
    for _ in range(100):
        text = page.text_content("#status") or ""
        if text:
            return text
        time.sleep(0.05)
    return ""


def clear(page: Any) -> None:
    page.locator("#status").evaluate("e => { e.textContent = '' }")


def test_1_enrol_refuses_a_wrong_code_then_accepts_the_right_one_once(world: World) -> None:
    page = world.page
    page.goto(world.base + "/enroll")
    page.fill("#code", "wrong")
    page.click("#go")
    assert "not valid" in status(page)
    clear(page)
    page.fill("#code", "code-1234")
    page.click("#go")
    assert "can now approve" in status(page)
    assert len(world.approver.keys) == 1
    clear(page)
    page.click("#go")  # the code is single-use
    assert "not valid" in status(page)


def test_2_metadata_publishes_the_device_key(world: World) -> None:
    path = metadata_url(ISSUER).split(ISSUER.split("//")[1], 1)[1]
    doc = json.loads(urllib.request.urlopen(world.base + path).read())
    from oac.jws import thumbprint

    assert doc["issuer"] == ISSUER and len(doc["keys"]) == 1
    assert keyset_from([(ISSUER, doc)]).issuer(thumbprint(doc["keys"][0])) == ISSUER


def test_3_approve_signs_in_the_browser_and_verifies_with_the_sdk(world: World) -> None:
    p, action = world.ask({"restaurant": "Nobu", "time": "Fri 7:30 pm", "party": 2, "note": "window seat"}, "Book Nobu, Fri 7:30 pm, 2 people")
    page = world.page
    page.goto(f"{world.base}/consent?r={p['id']}")
    page.wait_for_selector("#buttons:not([hidden])")
    shown = page.text_content("#fields")
    assert "Nobu" in shown and "window seat" in shown and "compensate" in shown and "Free cancellation" in shown
    page.click("#approve")
    assert "Approved" in status(page)
    token = world.delivered[-1]
    payload = verify_consent(token, keys=world.approver.keyset(), executor=EXECUTOR, sub=PERSON, previews=[p], actions=[action],
                             profiles={"book_table": PROFILE}, now=int(time.time()), nonces=MemoryNonces())
    assert payload["signer"]["kind"] == "device"
    assert verify(token, world.approver.keyset(), "oac-consent+jws")["iss"] == ISSUER


def test_4_decline_delivers_nothing(world: World) -> None:
    p, _ = world.ask({"restaurant": "Nobu", "time": "Sat", "party": 4}, "Book Nobu, Sat, 4 people")
    before = len(world.delivered)
    page = world.page
    page.goto(f"{world.base}/consent?r={p['id']}")
    page.wait_for_selector("#buttons:not([hidden])")
    page.click("#decline")
    assert "Declined" in status(page)
    assert len(world.delivered) == before and p["id"] in world.approver.declined


def test_5_hostile_preview_text_is_shown_as_text(world: World) -> None:
    p, _ = world.ask({"restaurant": "<img src=x onerror=document.title='pwned'>", "time": "Sun", "party": 2}, "<b>bold?</b>")
    page = world.page
    page.goto(f"{world.base}/consent?r={p['id']}")
    page.wait_for_selector("#buttons:not([hidden])")
    assert page.locator("img").count() == 0 and page.locator("#summary b").count() == 0 and page.title() != "pwned"


def test_6_unknown_request_and_other_origin_are_refused(world: World) -> None:
    page = world.page
    page.goto(f"{world.base}/consent?r=pv_nope")
    assert "unknown" in status(page)
    req = urllib.request.Request(world.base + "/api/consent", data=b'{"token":"x"}', method="POST",
                                 headers={"content-type": "application/json", "origin": "https://evil.example"})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 403
