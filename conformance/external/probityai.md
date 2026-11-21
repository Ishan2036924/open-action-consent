# probityai agent-evidence-vectors against the OAC Python SDK

Results of an outside corpus run against OAC. We did not write these cases. We did write the harness that runs
them, so read this as an outside test set with our own runner, not as an independent audit.

## The corpus

| item | value |
|---|---|
| owner and repository | probityai, https://github.com/probityai/agent-evidence-vectors |
| license | Apache-2.0 |
| version | project release v0.37.1 at the time of the run; data pinned to commit `517f7748013a665cbdd2eb71a80afe6c2273cf76` (2026-11-20) |
| directories used | `corpora/vectors-receipt-chain-end` (24 cases), `corpora/vectors-anchored-chain` (17 cases) |
| format | one directory per case: `case.json`, a store as JSON lines, an optional `head.json` or `anchor.json`; expected verdict and reason per case in `MANIFEST.json` (verdicts `verified`, `prefix`, `rejected`) |
| record formats | receipt-chain-end: signed action receipts, each with a hash link, a sequence number per signing key, session open and close records and key rotation markers. anchored-chain: signed records, each naming the digest of the line before it, and one anchor signed by a key the store does not hold |

We read the data files only. We did not install their package and did not run any of their code. This repository
does not copy their data: Apache-2.0 would allow it, but a pinned link is cleaner, so you download the files
yourself (commands below). The adapter refuses to run if a file differs from the digest in their `MANIFEST.json`.

## How cases were mapped

The adapter (`probityai_adapter.py`) reads each case, rebuilds it as OAC receipts and anchors signed with
throwaway keys, runs `verify_export`, and compares the outcome with the corpus verdict through the table below.

What the adapter does by itself, from their bytes: it checks their own Ed25519 signatures and hash links, because
OAC cannot read their record format. A receipt whose signature fails there becomes an OAC receipt edited after
signing. A receipt signed by a key the case does not trust becomes an OAC receipt signed by a key the verifier does
not hold. A link that points at another receipt in the file becomes an OAC `prev` that names that receipt. A record
of another chain becomes a receipt for another person (`sub`). A repeated JSON member becomes a signed receipt payload
with a repeated member. Sequence numbers come from the case (`chain_seq + 1`; position + 1 in the anchored suite,
whose records have none).

What OAC decides: everything else, that is, `seq`, `prev`, issuer, subject, signature, strict JSON, anchors and the
completeness report.

A retained head or anchor with a hash becomes an OAC anchor, a seal signed by a party that is not the executor.
That is the closest OAC object to "a head the consumer kept outside the writer's reach". A head with only a number
becomes the verifier's own count (`expect` without `head`). If the named receipt is not in the shown store, the
anchor names a head OAC cannot match, at the sequence the case gives.

| corpus reason | OAC must report |
|---|---|
| `end_proven_head`, `chain_anchored` | status `complete` |
| `end_proven_close` | status `complete`, only where a final retained head names the last receipt (the close itself is not used) |
| `end_unproven` | status `prefix` (any reason) |
| `records_after_last_anchor` | status `prefix`, reason `unanchored_tail` |
| `head_missing` | `chain_truncated` or `seal_mismatch` (the corpus has one reason where OAC has two) |
| `anchored_head_missing` | `chain_truncated` |
| `anchored_head_mismatch` | `seal_mismatch` |
| `chain_link_broken` | `chain_broken` or `chain_seq` |
| `signature_invalid`, `anchor_signature_invalid` | `bad_signature` or `unknown_key` |
| `signer_untrusted` | `unknown_key` |
| `record_from_other_chain` | `subject_mismatch` |
| `store_not_strict_json` | `malformed` |
| `utf16-member-order-*` | no export run; `oac.jcs` bytes must reproduce the signed bytes (rfc8785 case) or must not (code-point case) |

Not applicable, with the reason, in the results below: a signed run close (OAC has none), in-chain key rotation
markers and endorsements (OAC takes keys from issuer metadata), per-key sequence restarts (OAC numbers receipts
continuously per person), and a retained head marked final (an OAC anchor has no such flag).

## Results

Totals: 41 cases, 30 pass, 1 fail, 10 not applicable. receipt-chain-end: 13 pass, 1 fail, 10 not applicable.
anchored-chain: 17 pass, 0 fail, 0 not applicable.

"OAC says" is what the verifier returned. For not applicable cases it is shown only when the pipeline could run, and
only for information. "unsigned count instead" repeats a case with the head given as the verifier's own unsigned
count: OAC never says `complete` for it, as spec 8.4 requires.

| suite | case | corpus verdict | result | OAC says | note |
|---|---|---|---|---|---|
| receipt-chain-end | control-closed-run | verified/end_proven_close | NOT APPLICABLE | prefix/no_anchor | the verdict rests on a signed run close; OAC has no close marker |
| receipt-chain-end | control-closed-run-retained-head | verified/end_proven_close | PASS | complete | unsigned count instead: status=prefix/no_anchor |
| receipt-chain-end | control-open-prefix | prefix/end_unproven | PASS | prefix/no_anchor |  |
| receipt-chain-end | control-open-run-final-head | verified/end_proven_head | PASS | complete | unsigned count instead: status=prefix/no_anchor |
| receipt-chain-end | control-rotation-endorsed | verified/end_proven_close | NOT APPLICABLE | not run | in-chain key rotation marker, old-key endorsement and close; OAC takes keys from issuer metadata (spec 3.5) |
| receipt-chain-end | control-timestamp-tie | verified/end_proven_close | NOT APPLICABLE | prefix/no_anchor | the verdict rests on a signed run close; OAC has no close marker |
| receipt-chain-end | tail-truncation | prefix/end_unproven | PASS | prefix/no_anchor |  |
| receipt-chain-end | tail-truncation-retained-head | rejected/head_missing | PASS | error chain_truncated | unsigned count instead: error=chain_truncated |
| receipt-chain-end | prefix-replay-shared-session-close | prefix/end_unproven | PASS | prefix/no_anchor |  |
| receipt-chain-end | prefix-replay-other-run | rejected/head_missing | PASS | error chain_truncated | unsigned count instead: error=chain_truncated |
| receipt-chain-end | fork-branch-against-retained-head | rejected/head_missing | PASS | error seal_mismatch | unsigned count instead: error=seal_mismatch |
| receipt-chain-end | fork-branch-against-retained-seq | prefix/end_unproven | PASS | prefix/no_anchor |  |
| receipt-chain-end | fork-both-branches | rejected/chain_link_broken | PASS | error chain_seq |  |
| receipt-chain-end | rotation-resigned-tail-keys-pinned | rejected/rotation_unendorsed | NOT APPLICABLE | not run | needs an in-chain rotation marker and endorsement; OAC has neither |
| receipt-chain-end | rotation-resigned-tail-endorsement | rejected/rotation_unendorsed | NOT APPLICABLE | not run | needs an in-chain rotation marker and endorsement; OAC has neither |
| receipt-chain-end | stale-head-honest-extension | verified/end_proven_close | NOT APPLICABLE | prefix/unanchored_tail | the verdict rests on a signed close that follows an interim head; OAC has no close marker |
| receipt-chain-end | stale-head-truncated-to-it | prefix/end_unproven | FAIL | complete | unsigned count instead: status=prefix/no_anchor |
| receipt-chain-end | seq-reset-hides-gap | rejected/head_position_mismatch | NOT APPLICABLE | error chain_truncated | hazard is a per-key sequence restart; OAC numbers receipts continuously per person |
| receipt-chain-end | reorder-timestamp-tie | rejected/chain_link_broken | PASS | error chain_seq |  |
| receipt-chain-end | signature-tamper | rejected/signature_invalid | PASS | error bad_signature |  |
| receipt-chain-end | untrusted-genesis-key | rejected/signer_untrusted | PASS | error unknown_key |  |
| receipt-chain-end | close-count-forged | rejected/close_binding_invalid | NOT APPLICABLE | prefix/no_anchor | tests the receipt count inside a signed close; OAC has no close marker |
| receipt-chain-end | final-head-not-at-end | rejected/head_not_final | NOT APPLICABLE | prefix/unanchored_tail | the retained head is marked final and the chain must end there; an OAC anchor carries no final flag |
| receipt-chain-end | seq-reset-control-endorsed | verified/end_proven_close | NOT APPLICABLE | not run | sequence numbers restart at each key rotation; OAC numbers receipts continuously per person |
| anchored-chain | intact | verified/chain_anchored | PASS | complete |  |
| anchored-chain | records-after-last-anchor | verified/records_after_last_anchor | PASS | prefix/unanchored_tail |  |
| anchored-chain | t1-content-tamper | rejected/signature_invalid | PASS | error bad_signature |  |
| anchored-chain | t2-tail-removal | rejected/anchored_head_missing | PASS | error chain_truncated |  |
| anchored-chain | t2-tail-removal-after-last-anchor | verified/chain_anchored | PASS | complete |  |
| anchored-chain | t3-middle-deletion | rejected/chain_link_broken | PASS | error chain_broken |  |
| anchored-chain | t4-reorder | rejected/chain_link_broken | PASS | error chain_broken |  |
| anchored-chain | t5-forged-insertion | rejected/signature_invalid | PASS | error unknown_key |  |
| anchored-chain | t6-cross-context-replay | rejected/record_from_other_chain | PASS | error subject_mismatch |  |
| anchored-chain | t7-rollback-older-record | rejected/chain_link_broken | PASS | error chain_broken |  |
| anchored-chain | t8-metadata-tamper | rejected/signature_invalid | PASS | error bad_signature |  |
| anchored-chain | t9-snapshot-rollback | rejected/anchored_head_missing | PASS | error chain_truncated |  |
| anchored-chain | rollback-to-abandoned-branch | rejected/anchored_head_mismatch | PASS | error seal_mismatch |  |
| anchored-chain | tail-removal-reanchored | rejected/anchor_signature_invalid | PASS | error unknown_key | extra (not counted): same anchor signed with the executor's key gives error anchor_not_independent |
| anchored-chain | repeated-member-tail | rejected/store_not_strict_json | PASS | error malformed |  |
| anchored-chain | utf16-member-order-rfc8785 | verified/chain_anchored | PASS | complete | direct check of oac.jcs canonical bytes against the signed bytes |
| anchored-chain | utf16-member-order-code-point | rejected/signature_invalid | PASS | error bad_signature | direct check of oac.jcs canonical bytes against the signed bytes |

## The one failure

Case `stale-head-truncated-to-it` (receipt-chain-end). Input: a chain of 4 receipts (open plus 3 actions), every
signature and link valid, cut exactly at an interim head the consumer retained: `kind` `interim`, `receipt_index` 3,
`receipt_hash` of the 4th receipt. Expected: `prefix`, `end_unproven`: an interim head proves that a prefix was
written, not that nothing followed. Actual: `verify_export` returns `status: complete`, `proven_to: 4`, `reason: null`.

Cause: OAC anchors say "the chain had reached this receipt", with no final or interim flag, and status `complete`
means complete up to the latest anchor (spec 8.4, section 12). So a writer who cuts the tail exactly at an old
anchor gets `complete`. The spec already says records after the latest anchor are not protected, so this follows
from the design. The word `complete` is still stronger than the corpus allows. Two ways out, neither made here:
document that an anchor must be taken when the run stops, or let an anchor say whether it is final.

With the same head given as an unsigned count, OAC reports `prefix` (`no_anchor`), which matches the corpus.

## Limits of this run

- The adapter is ours. It reads their format itself, so a bug in it can hide or invent a result.
- Mapping choices matter. The biggest one: a retained head becomes a signed anchor from an independent signer. A
  consumer's own unsigned copy would give `prefix` in OAC, by design, in every such case.
- A pass means OAC gave a verdict that fits the mapping table, not that it gave their exact reason code. Where the
  table lists two codes, the table above shows which one OAC returned.
- Ten cases test things OAC does not have. They say nothing about OAC being right or wrong.
- The cases share one small shape (about 4 to 12 records). They do not test scale.
- Run against OAC SDK 0.5.1 (`sdk/python`), commit `3dd4bc8` of this repository. Keys are fresh on each run.

## Reproduce

From the root of this repository. The Python needs `cryptography` (the SDK needs it too).

```
SHA=517f7748013a665cbdd2eb71a80afe6c2273cf76
DATA=$(mktemp -d)
gh api "repos/probityai/agent-evidence-vectors/git/trees/$SHA?recursive=1" --jq '.tree[] | select(.type=="blob") | select(.path|test("^corpora/vectors-(receipt-chain-end|anchored-chain)/(MANIFEST.json|cases/.*\\.(json|jsonl))$")) | .path' |
while read p; do mkdir -p "$DATA/$(dirname "$p")"; curl -sfL "https://raw.githubusercontent.com/probityai/agent-evidence-vectors/$SHA/$p" -o "$DATA/$p"; done
python -I conformance/external/probityai_adapter.py --data "$DATA"
```

That downloads 115 JSON and JSONL files and nothing else. `python -I` ignores `PYTHONPATH`, so the adapter finds the
SDK through `--oac-src` (default `sdk/python/src` next to this folder).
