"""Approval tiers (spec 4). A hint can raise the tier, never lower it."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from oac import shapes
from oac.errors import OACError

ORDER = "ABCD"


def higher(*tiers: str) -> str:
    return max(tiers, key=ORDER.index)


def implied(profile: Mapping[str, Any]) -> str:
    effect, kind = profile["effect"], profile["undo"]["kind"]
    if effect == "read":
        return "A"
    if effect in ("write", "delete") and kind == "native":
        return "B"
    return "C"  # send, pay, and any write or delete that cannot be undone in one step


def tier_for(
    profile: Mapping[str, Any], *, policy_floor: str = "A", tainted: bool = False, hint: str | None = None
) -> str:
    shapes.profile(profile)
    tiers = [implied(profile), profile["tier_floor"], policy_floor]
    if tainted and profile["effect"] != "read":
        tiers.append("C")  # outside text reached this run: anything that acts asks first
    if hint is not None:
        tiers.append(hint)
    for t in tiers:
        if t not in ("A", "B", "C", "D"):
            raise OACError("malformed", f"unknown tier {t!r}")
    return higher(*tiers)
