"""Run two corpora of the probityai/agent-evidence-vectors project against the OAC Python SDK.

Data: https://github.com/probityai/agent-evidence-vectors (Apache-2.0), directories
corpora/vectors-receipt-chain-end and corpora/vectors-anchored-chain, pinned commit
517f7748013a665cbdd2eb71a80afe6c2273cf76. This file does not ship their data. Download the
JSON files yourself (see conformance/external/probityai.md) and pass the directory that holds
`corpora/` as --data.

What it does: each case is read as data (their code is never run), rebuilt as OAC receipts and
anchors signed with throwaway keys, and judged by oac.verify_export. The outcome is compared with
the corpus verdict through the explicit table MAPPING below. A case whose concept OAC lacks is
reported NOT APPLICABLE with its reason, never forced to pass.

Run with: python -I probityai_adapter.py --data DIR [--oac-src sdk/python/src]
Needs the `cryptography` package, which the OAC SDK already needs. Throwaway keys are fresh on
every run, so nothing here is a secret and no verdict depends on a key value.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ap = argparse.ArgumentParser()
ap.add_argument("--data", required=True, help="directory that holds corpora/vectors-*")
ap.add_argument("--oac-src", default=str(HERE.parent.parent / "sdk" / "python" / "src"))
ARGS = ap.parse_args()
sys.path.insert(0, ARGS.oac_src)  # python -I ignores PYTHONPATH, so the path is passed on purpose

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

import oac  # noqa: E402
from oac import KeySet, OACError, digest, generate, make_receipt, make_seal, token_digest, verify_export  # noqa: E402
from oac.jcs import canonical_bytes  # noqa: E402
from oac.jws import b64url  # noqa: E402
from oac.receipts import TYP  # noqa: E402

PINNED = "517f7748013a665cbdd2eb71a80afe6c2273cf76"
EX, SIGNER, PERSON, NOW = "https://executor.example/oac", "https://signer.example", "person:probity", 1_800_000_000
EXEC, USER, ROGUE = generate(), generate(), generate()
# The anchor keys also hold the executor's key on purpose: a verifier that trusts it must still refuse it as an anchor (8.4).
KEYS, USER_KEYS = KeySet({EX: [EXEC.jwk]}), KeySet({SIGNER: [USER.jwk], EX: [EXEC.jwk]})

# corpus reason -> what OAC must report. ("complete",) | ("prefix", {reasons} or None) | ("error", {codes})
# Where the corpus has one reason for two OAC refusals, both are listed and the actual one is printed.
MAPPING: dict[str, tuple[Any, ...]] = {
    "end_proven_head": ("complete",),
    "chain_anchored": ("complete",),
    "end_proven_close": ("complete",),  # used only where a retained final head also names the last receipt
    "end_unproven": ("prefix", None),
    "records_after_last_anchor": ("prefix", {"unanchored_tail"}),
    "head_missing": ("error", {"chain_truncated", "seal_mismatch"}),
    "anchored_head_missing": ("error", {"chain_truncated"}),
    "anchored_head_mismatch": ("error", {"seal_mismatch"}),
    "chain_link_broken": ("error", {"chain_broken", "chain_seq"}),
    "signature_invalid": ("error", {"bad_signature", "unknown_key"}),
    "signer_untrusted": ("error", {"unknown_key"}),
    "anchor_signature_invalid": ("error", {"bad_signature", "unknown_key"}),
    "record_from_other_chain": ("error", {"subject_mismatch"}),
    "store_not_strict_json": ("error", {"malformed"}),
}

# Cases whose concept OAC does not have. The reason is printed. Where the pipeline can still run,
# what OAC says is printed beside it, for information only.
NOT_APPLICABLE = {
    "control-closed-run": "the verdict rests on a signed run close; OAC has no close marker",
    "control-timestamp-tie": "the verdict rests on a signed run close; OAC has no close marker",
    "close-count-forged": "tests the receipt count inside a signed close; OAC has no close marker",
    "stale-head-honest-extension": "the verdict rests on a signed close that follows an interim head; OAC has no close marker",
    "final-head-not-at-end": "the retained head is marked final and the chain must end there; an OAC anchor carries no final flag",
    "control-rotation-endorsed": "in-chain key rotation marker, old-key endorsement and close; OAC takes keys from issuer metadata (spec 3.5)",
    "rotation-resigned-tail-keys-pinned": "needs an in-chain rotation marker and endorsement; OAC has neither",
    "rotation-resigned-tail-endorsement": "needs an in-chain rotation marker and endorsement; OAC has neither",
    "seq-reset-control-endorsed": "sequence numbers restart at each key rotation; OAC numbers receipts continuously per person",
    "seq-reset-hides-gap": "hazard is a per-key sequence restart; OAC numbers receipts continuously per person",
}


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def no_dups(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("repeated member " + k)
        out[k] = v
    return out


def ed_ok(pub_hex: str, sig: bytes, msg: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


class Row:
    """One stored record, reduced to the facts OAC needs."""

    def __init__(self, raw: bytes, seq: int, sub: str, sig_ok: bool, trusted: bool, prev_hash: str | None,
                 dup: bool, action: Any) -> None:
        self.raw, self.hash = raw, sha(raw)
        self.seq, self.sub, self.sig_ok, self.trusted = seq, sub, sig_ok, trusted
        self.prev_hash, self.dup, self.action = prev_hash, dup, action


def rebuild(rows: list[Row]) -> list[str]:
    """Rows to OAC receipts. A row's prev is the OAC digest of the row it names by hash, else a digest no row has."""
    tokens: list[str] = []
    index = {r.hash: i for i, r in enumerate(rows)}
    for i, r in enumerate(rows):
        prev = None
        if r.prev_hash is not None:
            j = index.get(r.prev_hash)
            prev = token_digest(tokens[j]) if j is not None and j < i else digest({"unresolved_link": r.prev_hash})
        if r.seq == 1:
            prev = None
        payload = {"iss": EX, "sub": r.sub, "seq": r.seq, "prev": prev, "iat": NOW + r.seq, "tool": "probity.record", "tier": "A",
                   "authority": {"kind": "tier"}, "action": digest(r.action), "outcome": "ok", "result": digest({"ok": True}),
                   "undo": {"kind": "none"}}
        if r.dup:  # two `tool` members under one valid signature
            body = canonical_bytes(payload)
            head = b64url(canonical_bytes({"alg": "EdDSA", "kid": EXEC.kid, "typ": TYP}))
            signing = head + "." + b64url(b'{"tool":"probity.forged",' + body[1:])
            tokens.append(signing + "." + b64url(EXEC.private.sign(signing.encode())))
        elif not r.trusted:
            tokens.append(make_receipt(key=ROGUE, payload=payload))
        else:
            tok = make_receipt(key=EXEC, payload=payload)
            if not r.sig_ok:  # edited after signing: the payload changes, the signature stays
                h, p, s = tok.split(".")
                p = b64url(canonical_bytes({**payload, "iat": payload["iat"] + 1}))
                tok = ".".join((h, p, s))
            tokens.append(tok)
    return tokens


def judge(rows: list[Row], head: dict[str, Any] | None, anchor_ok: bool = True, anchor_by: Any = None) -> tuple[str, Any]:
    """Run verify_export. head = {hash, index, seq, sub} (hash may be None), as the corpus kept it."""
    tokens = rebuild(rows)
    anchors: list[str] = []
    expect = None
    if head is not None:
        idx = next((i for i, r in enumerate(rows) if r.hash == head["hash"]), None) if head["hash"] else None
        if head["hash"] is None:
            expect = {"seq": head["seq"]}  # a number with no hash: only the verifier's own count
        else:
            seq = rows[idx].seq if idx is not None else head["seq"]
            tok = tokens[idx] if idx is not None else "retained-head:" + head["hash"]
            key = anchor_by or (USER if anchor_ok else ROGUE)
            iss = EX if anchor_by is EXEC else SIGNER
            anchors = [make_seal(key=key, iss=iss, sub=head["sub"], executor=EX, seq=seq, head_token=tok, now=NOW)]
    try:
        return "report", verify_export(tokens, keys=KEYS, executor=EX, anchors=anchors, anchor_keys=USER_KEYS, expect=expect)
    except OACError as e:
        return "error", e.code


def retained_as_count(rows: list[Row], head: dict[str, Any]) -> str:
    """Same head, but as the verifier's own unsigned count (spec 8.4): it can refuse an export, never prove one."""
    tokens = rebuild(rows)
    idx = next((i for i, r in enumerate(rows) if r.hash == head["hash"]), None)
    exp = {"seq": rows[idx].seq if idx is not None else head["seq"],
           "head": token_digest(tokens[idx] if idx is not None else "retained-head:" + head["hash"])}
    try:
        r = verify_export(tokens, keys=KEYS, executor=EX, expect=exp)
        return "status=" + r["status"] + "/" + str(r["reason"])
    except OACError as e:
        return "error=" + e.code


def show(kind: str, v: Any) -> str:
    return f"{v['status']}" + (f"/{v['reason']}" if v["reason"] else "") if kind == "report" else f"error {v}"


def compare(expected_reason: str, kind: str, v: Any) -> bool:
    want = MAPPING[expected_reason]
    if want[0] == "complete":
        return kind == "report" and v["status"] == "complete"
    if want[0] == "prefix":
        return kind == "report" and v["status"] == "prefix" and (want[1] is None or v["reason"] in want[1])
    return kind == "error" and v in want[1]


def jl(path: Path) -> list[bytes]:
    return [x for x in path.read_bytes().split(b"\n") if x]


# ---------------------------------------------------------------- receipt-chain-end


def chain_end_rows(d: Path, case: dict[str, Any]) -> tuple[list[Row], bool]:
    trust = case["trust"]
    ok_keys = set(trust["root_keys"]) | set(trust["pinned_keys"])
    lines = jl(d / case["chain"])
    parsed = [json.loads(x) for x in lines]
    rotated = any("key_transition" in p["action_record"] for p in parsed)
    rows = []
    for i, (raw, p) in enumerate(zip(lines, parsed)):
        rec = p["action_record"]
        msg = hashlib.sha256(json.dumps(rec, separators=(",", ":"), ensure_ascii=False).encode()).digest()
        sig_ok = ed_ok(p["signer_key"], bytes.fromhex(p["signature"].removeprefix("ed25519:")), msg)
        first = i == 0
        rows.append(Row(raw, (i + 1) if rotated else rec["chain_seq"] + 1, PERSON, sig_ok, p["signer_key"] in ok_keys,
                        None if first else rec["chain_prev_hash"], False, rec))
    return rows, rotated


def chain_end_head(d: Path, case: dict[str, Any], rows: list[Row]) -> dict[str, Any] | None:
    if "head" not in case:
        return None
    h = json.loads((d / case["head"]).read_text())
    seq = (h["receipt_index"] if "receipt_index" in h else h["final_seq"]) + 1
    return {"hash": h.get("receipt_hash"), "seq": seq, "sub": PERSON, "kind": h["kind"]}


# ---------------------------------------------------------------- anchored-chain


def anchored_rows(d: Path, case: dict[str, Any]) -> list[Row]:
    prod = case["keys"]["producer"]
    rows = []
    for i, raw in enumerate(jl(d / case["store"])):
        try:
            env = json.loads(raw, object_pairs_hook=no_dups)
            dup = False
        except ValueError:
            env, dup = json.loads(raw), True
        rec = env["record"]
        sig_ok = env["kid"] == "producer" and ed_ok(prod, base64.b64decode(env["sig"]), canonical_bytes(rec))
        trusted = env["kid"] == "producer"
        sub = PERSON if rec["chain"] == case["chain"] else "person:" + rec["chain"]
        rows.append(Row(raw, i + 1, sub, sig_ok or dup, trusted, None if rec["prev"] == "0" * 64 else rec["prev"], dup, rec))
    return rows


def anchored_head(d: Path, case: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    a = json.loads((d / case["anchor"]).read_text())
    body = a["anchor"]
    key = case["keys"].get(a["kid"])
    ok = key is not None and ed_ok(key, base64.b64decode(a["sig"]), canonical_bytes(body))
    return {"hash": body["head"], "seq": body["index"] + 1, "sub": PERSON}, ok


def utf16_case(d: Path, case: dict[str, Any]) -> tuple[str, Any]:
    """Direct test of oac.jcs: does OAC's canonical form reproduce the bytes the producer signed?"""
    bad = 0
    for raw in jl(d / case["store"]):
        env = json.loads(raw)
        if not ed_ok(case["keys"]["producer"], base64.b64decode(env["sig"]), canonical_bytes(env["record"])):
            bad += 1
    return ("error", "bad_signature") if bad else ("report", {"status": "complete", "reason": None})


def main() -> int:
    base = Path(ARGS.data) / "corpora"
    results: list[tuple[str, str, str, str, str, str]] = []  # suite, id, expected, status, oac, note

    for suite in ("vectors-receipt-chain-end", "vectors-anchored-chain"):
        man = json.loads((base / suite / "MANIFEST.json").read_text())
        for v in man["vectors"]:
            for name, want_hash in v["files"].items():  # the download must be the pinned bytes
                if sha((base / suite / v["path"] / name).read_bytes()) != want_hash:
                    sys.exit(f"{suite}/{v['id']}/{name}: file differs from MANIFEST.json")
            cid, exp = v["id"], v["expected"]
            d = base / suite / v["path"]
            case = json.loads((d / "case.json").read_text())
            want = f"{exp['decision']}/{exp['reason']}"
            note = ""
            if suite == "vectors-anchored-chain" and cid.startswith("utf16-"):
                kind, val = utf16_case(d, case)
                note = "direct check of oac.jcs canonical bytes against the signed bytes"
                head = None
            elif suite == "vectors-receipt-chain-end":
                rows, rotated = chain_end_rows(d, case)
                head = chain_end_head(d, case, rows)
                kind, val = judge(rows, head)
                if head and head["hash"]:
                    note = "unsigned count instead: " + retained_as_count(rows, head)
            else:
                rows = anchored_rows(d, case)
                head, anchor_ok = anchored_head(d, case)
                kind, val = judge(rows, head, anchor_ok=anchor_ok)
                if cid == "tail-removal-reanchored":
                    k2, v2 = judge(rows, head, anchor_by=EXEC)
                    note = "extra (not counted): same anchor signed with the executor's key gives " + show(k2, v2)
            got = show(kind, val)
            if cid in NOT_APPLICABLE:
                if suite == "vectors-receipt-chain-end" and rotated:
                    got = "not run"
                results.append((suite, cid, want, "NOT APPLICABLE", got, NOT_APPLICABLE[cid]))
                continue
            status = "PASS" if compare(exp["reason"], kind, val) else "FAIL"
            results.append((suite, cid, want, status, got, note))

    print("| suite | case | corpus verdict | result | OAC says | note |")
    print("|---|---|---|---|---|---|")
    for s, c, w, st, g, n in results:
        print(f"| {s.removeprefix('vectors-')} | {c} | {w} | {st} | {g} | {n} |")
    tot = {k: sum(1 for r in results if r[3] == k) for k in ("PASS", "FAIL", "NOT APPLICABLE")}
    print(f"\ncases {len(results)}: pass {tot['PASS']}, fail {tot['FAIL']}, not applicable {tot['NOT APPLICABLE']}")
    print(f"oac {oac.__version__}; corpus commit {PINNED}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
