"""All vectors pass, and switching off a check turns named vectors red."""

from __future__ import annotations

from pathlib import Path

import pytest

import oac.consent
import oac.shapes
import oac.jws
import oac.mandate
import oac.occurrence
import oac.receipts
import oac.undo
import oac.webauthn
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
    ("undeclared arguments allowed", oac.shapes, "check_action", _noop, "model adds an undeclared bcc"),
    ("status bit ignored", oac.mandate, "is_revoked", lambda *a, **k: False, "the mandate's bit is set"),
    ("seals ignored", oac.receipts, "check_seals", _noop, "rewrote receipt 3 after the seal"),
    ("issuer binding off", oac.jws.KeySet, "issuer", lambda self, kid: "https://atlas.example/signer", "signs in another signer's name"),
    ("receipt rules off", oac.receipts, "check_semantics", _noop, "tier C on the tool's own say-so"),
    ("undo receipt rules off", oac.undo, "check_semantics", _noop, "undo of an invalid receipt"),
    ("device proof ignored", oac.consent, "verify_device_proof", _noop, "user present but not verified"),
    ("occurrence state ignored", oac.occurrence, "_refuse", _noop, "last attempt is unknown"),
    ("backup flags ignored", oac.webauthn, "BACKED_UP", 0, "backed up but not backup eligible"),
    ("device binding ignored", oac.webauthn, "BACKUP_ELIGIBLE", 0, "executor wants one bound to the device"),
]


@pytest.mark.parametrize("label,module,attr,fake,must_fail", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_each_check_is_load_bearing(monkeypatch, label, module, attr, fake, must_fail) -> None:
    monkeypatch.setattr(module, attr, fake)
    failures = failing()
    assert any(must_fail in f for f in failures), f"switching off '{label}' broke no vector"


def test_replay_check_is_load_bearing(monkeypatch) -> None:
    monkeypatch.setattr(oac.consent.MemoryNonces, "use_once", lambda self, jti, exp: True)
    assert any("replayed nonce" in f for f in failing())


def test_low_s_check_is_load_bearing(monkeypatch) -> None:
    monkeypatch.setattr(oac.jws, "_P256_ORDER", 2**300)  # n/2 huge: every s counts as low
    assert any("high-S twin" in f for f in failing())
