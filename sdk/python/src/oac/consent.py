"""Consent (spec section 6): the person's signed yes to one or more Previews. Verified by the executor right before
it runs the actions; checks run in the spec's order and the first failure is the one reported."""

from __future__ import annotations

import secrets
import threading
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from oac import shapes
from oac.errors import OACError
from oac.jws import KeySet, SigningKey, digest, sign, verify
from oac.preview import action_digest, check_binding
from oac.tiers import tier_for
from oac.webauthn import DeviceCheck, verify_device_proof

TYP = "oac-consent+jws"
MAX_S = 900  # a Consent lives at most 15 minutes
SKEW_S = 60  # clocks may differ this much


class NonceStore(Protocol):
    def use_once(self, jti: str, exp: int) -> bool:
        """Record jti until exp and return True, or return False if it was already recorded. Must be atomic: two
        callers with the same jti can never both get True."""
        ...


class MemoryNonces:
    """In-memory nonce store for tests and examples. Production stores do an atomic insert-if-absent (a unique key)
    and keep each jti until its exp has passed."""

    def __init__(self, seen: Sequence[str] = ()) -> None:
        self._seen: dict[str, int] = {j: 0 for j in seen}
        self._lock = threading.Lock()

    def use_once(self, jti: str, exp: int) -> bool:
        with self._lock:
            if jti in self._seen:
                return False
            self._seen[jti] = exp
            return True


def new_nonce() -> str:
    return secrets.token_urlsafe(18)


def make_consent(
    *,
    key: SigningKey,
    iss: str,
    sub: str,
    aud: str,
    previews: Sequence[Mapping[str, Any]],
    now: int,
    ttl: int = 300,
    jti: str | None = None,
    signer_kind: str = "custodial",
    payment: Mapping[str, Any] | None = None,
) -> str:
    payload: dict[str, Any] = {
        "oac": shapes.VERSION,
        "type": "consent",
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "jti": jti or new_nonce(),
        "iat": now,
        "exp": now + ttl,
        "items": [{"preview": digest(p), "action": p["action"]} for p in previews],
        "signer": {"kind": signer_kind},
    }
    if payment is not None:
        payload["payment"] = dict(payment)
    return sign(shapes.consent(payload), key, TYP)


def check_time(p: Mapping[str, Any], now: int, max_s: int) -> None:
    if p["iat"] > now + SKEW_S:
        raise OACError("not_yet_valid")
    if now >= p["exp"]:
        raise OACError("expired")
    if p["exp"] - p["iat"] > max_s or p["exp"] <= p["iat"]:
        raise OACError("lifetime_too_long")


def _payment(p: Mapping[str, Any], preview: Mapping[str, Any]) -> None:
    pay = p.get("payment")
    if pay is None:
        raise OACError("payment_missing", "a pay action needs consent.payment")
    f = preview["fields"]
    for name in ("amount_minor", "currency", "payee"):
        if f.get(name) != pay[name]:
            raise OACError("payment_mismatch", f"payment {name} differs from the preview")


def verify_consent(
    token: str,
    *,
    keys: KeySet,
    executor: str,
    sub: str,
    previews: Sequence[Mapping[str, Any]],
    actions: Sequence[Mapping[str, Any]],
    profiles: Mapping[str, Mapping[str, Any]],
    now: int,
    nonces: NonceStore,
    policy_floor: str = "A",
    tainted: bool = False,
    device: DeviceCheck | None = None,
) -> dict[str, Any]:
    """`sub` is the person this executor is acting for (from its own sign-in), never taken from the token."""
    p = verify(token, keys, TYP)
    shapes.consent(p)
    if p["aud"] != executor:
        raise OACError("wrong_audience")
    if p["sub"] != sub:
        raise OACError("subject_mismatch", "the consent is another person's")
    check_time(p, now, MAX_S)
    if len(p["items"]) != len(previews) or len(previews) != len(actions):
        raise OACError("preview_mismatch", "one preview and one action per item")
    pays = 0
    for item, preview, action in zip(p["items"], previews, actions):
        shapes.preview(preview)
        if digest(preview) != item["preview"]:
            raise OACError("preview_mismatch")
        if preview["action"] != item["action"] or action_digest(action) != item["action"]:
            raise OACError("action_mismatch")
        if preview["sub"] != p["sub"]:
            raise OACError("subject_mismatch")
        if preview["executor"] != executor:
            raise OACError("executor_mismatch")
        if now >= preview["exp"]:
            raise OACError("preview_expired")
        profile = profiles.get(action["tool"])
        if profile is None:
            raise OACError("unknown_tool")
        shapes.profile(profile)
        check_binding(preview, action, profile)
        if tier_for(profile, policy_floor=policy_floor, tainted=tainted) == "D":
            raise OACError("tier_d")
        if profile["effect"] == "pay":
            pays += 1
            if pays > 1:
                raise OACError("malformed", "one payment per consent")
            _payment(p, preview)
    if pays == 0 and "payment" in p:
        raise OACError("payment_mismatch", "payment given but no item pays")
    if device is not None:
        verify_device_proof(token, device)
    if not nonces.use_once(p["jti"], p["exp"]):
        raise OACError("replay")
    return p
