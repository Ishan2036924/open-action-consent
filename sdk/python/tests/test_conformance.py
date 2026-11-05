"""Every shared vector passes, and the runner really fails when a safety check is switched off (planted defects:
each mutation below must turn at least one named vector red)."""

from __future__ import annotations

from pathlib import Path

import pytest

import oac.consent
import oac.jws
import oac.mandate
import oac.receipts
import oac.undo
from oac.conformance import run

VECTORS = Path(__file__).resolve().parents[3] / "vectors"


def failing(monkeypatch: pytest.MonkeyPatch | None = None) -> list[str]:
    total, failures = run(VECTORS)
    assert total >= 100
    return failures


def test_all_vectors_pass() -> None:
    assert failing() == []


def _noop(*args: object, **kwargs: object) -> None:
    return None


MUTATIONS = [
    ("no signature check", oac.jws, "_check_sig", _noop, "forged: attacker signs"),
    ("no preview-to-argument binding", oac.consent, "check_binding", _noop, "preview fields do not match the arguments"),
    ("no time check on consents", oac.consent, "check_time", _noop, "lives longer than 15 minutes"),
    ("tier D treated as C", oac.consent, "tier_for", lambda *a, **k: "C", "tier D never runs, even with a yes"),
    ("any recipient allowed", oac.mandate, "_recipient_ok", lambda *a: True, "recipient outside the list"),
    ("receipt rules off", oac.receipts, "check_semantics", _noop, "tier C on the tool's own say-so"),
    ("undo receipt rules off", oac.undo, "check_semantics", _noop, "undo of an invalid receipt"),
]


@pytest.mark.parametrize("label,module,attr,fake,must_fail", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_each_check_is_load_bearing(monkeypatch, label, module, attr, fake, must_fail) -> None:
    monkeypatch.setattr(module, attr, fake)
    failures = failing()
    assert any(must_fail in f for f in failures), f"switching off '{label}' broke no vector"


def test_replay_check_is_load_bearing(monkeypatch) -> None:
    monkeypatch.setattr(oac.consent.MemoryNonces, "seen", lambda self, jti: False)
    assert any("replayed nonce" in f for f in failing())
