"""Run the shared vectors: python -m oac.conformance vectors"""

from __future__ import annotations

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
from oac.discovery import keyset_from, metadata_url
from oac.status import bit, decode
from oac.occurrence import MemoryOccurrences, claim
from oac.webauthn import DeviceCheck


def _consent(i: Mapping[str, Any]) -> Any:
    verify_consent(
        i["token"],
        keys=KeySet(i["keys"]),
        executor=i["executor"],
        sub=i["sub"],
        previews=i["previews"],
        actions=i["actions"],
        profiles=i["profiles"],
        now=i["now"],
        nonces=MemoryNonces(i.get("seen_nonces", [])),
        policy_floor=i.get("policy_floor", "A"),
        tainted=i.get("tainted", False),
        device=DeviceCheck(**i["device"]) if "device" in i else None,
    )
    return {"ok": True}


def _occurrence(i: Mapping[str, Any]) -> Any:
    key = ("person", "tool", "occurrence")
    claim(MemoryOccurrences({key: i["state"]} if i["state"] else None), key)
    return {"ok": True}


def _mandate(i: Mapping[str, Any]) -> Any:
    check_mandate(
        i["token"],
        keys=KeySet(i["keys"]),
        action=i["action"],
        profile=i["profile"],
        holder=i["holder"],
        sub=i["sub"],
        now=i["now"],
        tainted=i["tainted"],
        usage=i.get("usage"),
        revoked=i.get("revoked", []),
        status_lists=i.get("status_lists", {}),
    )
    return {"ok": True}


def _chain(i: Mapping[str, Any]) -> Any:
    verify_chain(i["tokens"], keys=KeySet(i["keys"]), executor=i["executor"], sub=i.get("sub"), seals=i.get("seals", []),
                 seal_keys=KeySet(i["seal_keys"]) if "seal_keys" in i else None)
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
        undone=i.get("undone", []),
        compensation=i.get("compensation"),
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
    "claim_occurrence": _occurrence,
    "status_bit": lambda i: {"revoked": bit(decode(i["encoded_list"]), i["index"])},
    "metadata_url": lambda i: {"url": metadata_url(i["iss"])},
    "keyset_from": lambda i: {"issuer": keyset_from([(d[0], d[1]) for d in i["docs"]]).issuer(i["kid"])},
}


def run_case(case: Mapping[str, Any]) -> Any:
    try:
        return OPS[case["op"]](case["input"])
    except OACError as e:
        return {"error": e.code}


def run(directory: Path) -> tuple[int, list[str]]:
    total, failures = 0, []
    for path in sorted(directory.glob("*.json")):
        for case in parse(path.read_bytes())["cases"]:  # the strict parser, as for anything off the wire
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
