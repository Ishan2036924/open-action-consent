"""Check schemas/ against the vectors: every object in a passing case validates, and the profile cases the schema can
express fail. Needs the `jsonschema` package (dev only): `python tools/check_schemas.py`."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent.parent
schemas = {p.stem.replace(".schema", ""): json.loads(p.read_text()) for p in (ROOT / "schemas").glob("*.schema.json")}
registry = Registry().with_resources((s["$id"], Resource.from_contents(s)) for s in schemas.values())
for s in schemas.values():
    Draft202012Validator.check_schema(s)
V = {name: Draft202012Validator(s, registry=registry) for name, s in schemas.items()}
TYP = {"oac-consent+jws": "consent", "oac-mandate+jws": "mandate", "oac-receipt+jws": "receipt", "oac-undo+jws": "undo"}


def part(token: str, i: int) -> dict:
    p = token.split(".")[i]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def tokens(inp: dict) -> list[str]:
    out = [inp[k] for k in ("token", "receipt_token") if isinstance(inp.get(k), str)]
    return out + list(inp.get("tokens", []))


checked, errors = 0, []
for path in sorted((ROOT / "vectors").glob("*.json")):
    for case in json.loads(path.read_text())["cases"]:
        inp, ok = case["input"], case["expect"] == {"ok": True}
        objs: list[tuple[str, dict]] = []
        if ok:
            objs += [("preview", p) for p in inp.get("previews", [])]
            objs += [("action-profile", p) for p in inp.get("profiles", {}).values()]
            if "profile" in inp:
                objs.append(("action-profile", inp["profile"]))
            for t in tokens(inp):
                objs.append((TYP[part(t, 0)["typ"]], part(t, 1)))
        for name, obj in objs:
            checked += 1
            errs = list(V[name].iter_errors(obj))
            if errs:
                errors.append(f"{path.name} :: {case['name']}: {name}: {errs[0].message}")
        if case["op"] == "profile" and not ok and case["name"] != "a read that claims an undo":
            checked += 1
            if V["action-profile"].is_valid(inp["profile"]):
                errors.append(f"{path.name} :: {case['name']}: schema accepted a malformed profile")
for e in errors:
    print("FAIL", e)
print(f"schemas: {checked - len(errors)}/{checked} checks passed")
sys.exit(1 if errors else 0)
