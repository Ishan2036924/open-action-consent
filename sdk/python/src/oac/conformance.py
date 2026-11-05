"""Conformance runner: `python -m oac.conformance <vectors dir>`. Runs every case in vectors/*.json against this SDK and
exits non-zero if any result differs from the expected one. The case format is in conformance/README.md; the
TypeScript SDK runs the same files."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from oac.consent import MemoryNonces, verify_consent
from oac.errors import OACError
from oac.jcs import canonical, parse
from oac.jws import KeySet, digest, sign
from oac.mandate import check_mandate, loosens
from oac.preview import check_binding
from oac.receipts import verify_chain
from oac import shapes
from oac.testing import vector_key
from oac.tiers import tier_for
from oac.undo import check_undo


def _consent(i: Mapping[str, Any]) -> Any:
    verify_consent(
        i["token"],
        keys=KeySet(i["keys"]),
        executor=i["executor"],
        previews=i["previews"],
        actions=i["actions"],
        profiles=i["profiles"],
        now=i["now"],
        nonces=MemoryNonces(i.get("seen_nonces", [])),
        policy_floor=i.get("policy_floor", "A"),
        tainted=i.get("tainted", False),
    )
    return {"ok": True}


def _mandate(i: Mapping[str, Any]) -> Any:
    check_mandate(
        i["token"],
        keys=KeySet(i["keys"]),
        action=i["action"],
        profile=i["profile"],
        holder=i["holder"],
        now=i["now"],
        usage=i.get("usage"),
        tainted=i.get("tainted", False),
    )
    return {"ok": True}


def _chain(i: Mapping[str, Any]) -> Any:
    verify_chain(i["tokens"], keys=KeySet(i["keys"]), executor=i["executor"], sub=i.get("sub"))
    return {"ok": True}


def _undo(i: Mapping[str, Any]) -> Any:
    check_undo(
        i["token"],
        keys=KeySet(i["keys"]),
        executor=i["executor"],
        receipt_token=i["receipt_token"],
        receipt_keys=KeySet(i["receipt_keys"]),
        now=i["now"],
        nonces=MemoryNonces(i.get("seen_nonces", [])),
    )
    return {"ok": True}


def _binding(i: Mapping[str, Any]) -> Any:
    check_binding(i["preview"], i["action"], i["profile"])
    return {"ok": True}


def _profile(i: Mapping[str, Any]) -> Any:
    shapes.profile(i["profile"])
    return {"ok": True}


OPS: dict[str, Callable[[Mapping[str, Any]], Any]] = {
    "jcs": lambda i: {"canonical": canonical(i["value"])},
    "parse": lambda i: {"canonical": canonical(parse(i["text"]))},
    "digest": lambda i: {"digest": digest(i["value"])},
    "tier": lambda i: {
        "tier": tier_for(i["profile"], policy_floor=i.get("policy_floor", "A"), tainted=i.get("tainted", False), hint=i.get("hint"))
    },
    "sign": lambda i: {"token": sign(i["payload"], vector_key(i["key"], i.get("alg", "EdDSA")), i["typ"])},
    "profile": _profile,
    "binding": _binding,
    "verify_consent": _consent,
    "check_mandate": _mandate,
    "loosens": lambda i: {"reasons": sorted(loosens(i["old"], i["new"]))},
    "verify_chain": _chain,
    "check_undo": _undo,
}


def run_case(case: Mapping[str, Any]) -> Any:
    try:
        return OPS[case["op"]](case["input"])
    except OACError as e:
        return {"error": e.code}


def run(directory: Path) -> tuple[int, list[str]]:
    total, failures = 0, []
    for path in sorted(directory.glob("*.json")):
        for case in json.loads(path.read_text())["cases"]:
            total += 1
            got = run_case(case)
            if got != case["expect"]:
                failures.append(f"{path.name} :: {case['name']}: expected {case['expect']}, got {got}")
    return total, failures


def main(argv: list[str]) -> int:
    directory = Path(argv[1] if len(argv) > 1 else "vectors")
    total, failures = run(directory)
    for f in failures:
        print("FAIL", f)
    print(f"oac conformance (python): {total - len(failures)}/{total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
