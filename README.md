# Open Action Consent (OAC)

[![ci](https://github.com/Ishan2036924/open-action-consent/actions/workflows/ci.yml/badge.svg)](https://github.com/Ishan2036924/open-action-consent/actions/workflows/ci.yml)

**A verifiable "yes" for things AI agents do for people.**

When an agent sends an email, books a table or pays, the person's approval is usually a button no one else can check.
OAC turns it into small signed objects anyone can verify:

```
Preview  ──>  Consent  ──>  action runs  ──>  Receipt  ──>  Undo
what will     the person's   only if the       what ran,      take it back, when
happen,       signature over signature, the    chained, with  the action allows it
built by the  that exact     binding and the   how to undo it
tool          preview        limits check out
```

- **Bound previews.** Every argument is declared by the tool and shown: structured fields (recipient, amount,
  payee, time) are checked against the call's real arguments, and the rest is shown unchanged. If the agent changes
  "2 people" to "20" after the yes, or slips in a `bcc`, the call is refused.
- **Tiers A–D.** Reads just run (A); undoable writes run with a receipt and an Undo (B); sends, payments and anything
  irreversible need a yes (C); some things never run (D). The tier is computed; a model can only make it stricter.
- **Mandates.** Standing, bounded permissions ("lunch under $25 at these two places, five times a day, for a week").
  Never for tier D, never after outside text has steered the run, and loosening one needs fresh proof.
- **Receipts and Undo.** Each action gets a signed, hash-chained receipt that says whether it can be undone
  natively, fixed with a cancel/refund, or not at all; and that is shown before the yes.
- **Payments by reference.** OAC never moves money or holds a card. A payment Consent points to the rail's own
  authorization (Stripe Link, AP2, Verifiable Intent) and must match the preview's amount and payee.

OAC sits **next to** MCP, A2A, AP2 and ACP, not on top of them. See [spec/mappings.md](spec/mappings.md).

## Quickstart (Python)

```python
from oac import build_preview, make_consent, verify_consent, generate, KeySet, MemoryNonces

profile = {"oac": "0.1", "type": "action-profile", "tool": "send_email", "effect": "send",
           "undo": {"kind": "none", "window_s": 0}, "tier_floor": "A",
           "binds": {"to": "to", "title": "subject"}, "other_args": ["body"]}
action = {"tool": "send_email", "args": {"to": ["sam@example.com"], "subject": "Lunch?", "body": "Friday 1 pm?"}}

preview = build_preview(profile=profile, action=action, executor="mail.example", sub="person:1",
                        summary="Email sam@example.com: Lunch?", now=1793836800)
user_key = generate()                      # lives with the person's signer, never with the model
consent = make_consent(key=user_key, iss="signer.example", sub="person:1", aud="mail.example",
                       previews=[preview], now=1793836800)
verify_consent(consent, keys=KeySet({"signer.example": [user_key.jwk]}), executor="mail.example",
               sub="person:1", previews=[preview], actions=[action], profiles={"send_email": profile},
               now=1793836810, nonces=MemoryNonces())
```

## What is here

| Path | What |
|---|---|
| [spec/oac-v0.1.md](spec/oac-v0.1.md) | the specification (normative) |
| [spec/mcp-extension.md](spec/mcp-extension.md) | how OAC rides on MCP 2026-07-28 (URL-mode elicitation, `_meta`), built to fit SEP-2848 and SEP-2793 |
| [spec/mappings.md](spec/mappings.md) | AP2, Verifiable Intent, Stripe, ACP, UCP, A2A, IETF receipt drafts |
| [spec/profiles/dispute.md](spec/profiles/dispute.md) | Dispute Evidence Pack |
| [schemas/](schemas/) | JSON Schema 2020-12 for every object |
| [vectors/](vectors/) | 205 conformance cases: valid ones and planted defects (forged signature, changed arguments, hidden bcc, two addresses in one, replay, expired, revoked or widened mandate, one signer speaking for another, signature twins, broken receipt chain, rewritten history under a seal, revoked bit, double undo, ...) |
| [sdk/python/](sdk/python/) | reference SDK (needs `cryptography`) |
| [sdk/typescript/](sdk/typescript/) | reference SDK (no dependencies, Node 23.6+) |
| [conformance/](conformance/) | vector format and how to run it |
| [examples/mcp-server/](examples/mcp-server/) | a small MCP server using the extension, and a demo with two attacks that fail |

## Check everything

```
tools/check_all.sh          # PYTHON=/path/to/python to choose an interpreter
```

Both SDKs pass the same vectors, Python verifies tokens signed by TypeScript, and a differential run of about 22,600
generated inputs gives identical answers in both. The Python tests also switch off each safety check one at a time
and confirm a vector fails, so a check that quietly stops working is caught.

## Status

Draft 0.1 ([changelog](CHANGELOG.md)). Not endorsed by any standards body. Feedback, implementations and reviews are
welcome: see [CONTRIBUTING.md](CONTRIBUTING.md), and report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

**OAC-conformant:** an implementation that passes every case in `vectors/` may say so and link to this repository.

## License

Code, schemas and test vectors: [Apache-2.0](LICENSE). Specification text: [CC BY 4.0](LICENSE-SPEC).
