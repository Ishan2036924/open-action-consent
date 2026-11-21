"""Deployment coverage (spec 13.2): a coverage statement and the bypass-check attempts become one result per effect."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from oac import shapes


def _row(row: Mapping[str, Any], tried: Sequence[Mapping[str, Any]]) -> str:
    if not tried:
        return "not_checked"
    if any(a["effect_occurred"] == "yes" for a in tried):
        return "bypass"
    skipped = {x["route"] for x in row["routes"]} - {a["route"] for a in tried}
    if row["records"] == "memory" or skipped or any(a["effect_occurred"] == "cannot_tell" for a in tried):
        return "incomplete"
    return "covered"


def coverage(statement: Sequence[Mapping[str, Any]] | None, attempts: Sequence[Mapping[str, Any]] | None) -> dict[str, Any]:
    """Four results per effect and for the whole claim, never a score. `statement_wrong`: an effect happened on a route the statement does not list."""
    rows, tried = shapes.coverage_statement(statement), shapes.coverage_attempts(attempts)
    listed = {r["effect"]: {x["route"] for x in r["routes"]} for r in rows}
    happened = [a for a in tried if a["effect_occurred"] == "yes"]
    effects = {r["effect"]: _row(r, [a for a in tried if a["effect"] == r["effect"]]) for r in rows}
    effects |= {a["effect"]: "bypass" for a in happened if a["effect"] not in listed}
    kinds = set(effects.values())
    if "bypass" in kinds:
        result = "bypass"
    elif kinds <= {"not_checked"}:
        result = "not_checked"
    else:
        result = "covered" if kinds == {"covered"} else "incomplete"
    wrong = any(a["route"] not in listed.get(a["effect"], ()) for a in happened)
    return {"result": result, "statement_wrong": wrong, "effects": effects}
