"""Each browser safety check is load-bearing: switch it off and a named test must fail."""

from __future__ import annotations

import sys

import pytest

if sys.version_info < (3, 11):
    from exceptiongroup import BaseExceptionGroup

import oac_browser
import oac_mcp
import test_gated_browser as t

pytestmark = pytest.mark.anyio


async def must_fail(coro) -> None:
    """The test must fail with an AssertionError (possibly wrapped in the SDK's task-group exception group)."""
    try:
        await coro
    except AssertionError:
        return
    except BaseExceptionGroup as g:  # noqa: F821 (3.11+; anyio's backport on 3.10)
        if g.subgroup(AssertionError) is not None:
            return
        raise
    raise AssertionError("switching the check off broke no test")


async def test_final_detector_matters(site: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oac_browser, "is_final", lambda el: False)
    await must_fail(t.test_final_button_cannot_be_clicked_without_submit(site))


async def test_page_change_check_matters(site: str, monkeypatch: pytest.MonkeyPatch) -> None:
    async def nothing(self, action, ctx):  # inspect switched off: no evidence, no comparison
        return {}

    monkeypatch.setattr(oac_mcp.OACExtension, "_look", nothing)
    await must_fail(t.test_page_changed_after_the_yes_is_refused(site))


async def test_captcha_detector_matters(site: str, monkeypatch: pytest.MonkeyPatch) -> None:
    import re

    monkeypatch.setattr(oac_browser, "CAPTCHA", re.compile(r"(?!x)x"))
    monkeypatch.setattr(oac_browser, "HUMAN_CHECK", re.compile(r"(?!x)x"))
    await must_fail(t.test_captcha_stops_everything(site))
