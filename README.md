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

## Install

| | Python | JavaScript / TypeScript |
|---|---|---|
| Core | `pip install open-action-consent` | `npm install open-action-consent` |
| MCP servers | `pip install "open-action-consent[mcp]"` → `oac.mcp` | `open-action-consent/mcp` (+ `@modelcontextprotocol/server`) |
| Gated Browser | `pip install "open-action-consent[browser]"` → `oac.browser`, command `oac-gated-browser` | |
| Approval page | `pip install "open-action-consent[approver]"` → `oac.approver` | |
| OpenAI Agents SDK | `pip install "open-action-consent[openai-agents]"` → `oac.openai_agents` | |
| LangGraph | `pip install "open-action-consent[langgraph]"` → `oac.langgraph` | |
| Vercel AI SDK | | `open-action-consent/vercel-ai` (+ `ai`) |
| Everything | `pip install "open-action-consent[all]"` | |

The core needs only `cryptography` (Python) or nothing (TypeScript); each part pulls in its framework only when you
ask for it.

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
| [vectors/](vectors/) | 230 conformance cases: valid ones and planted defects (forged signature, changed arguments, hidden bcc, two addresses in one, replay, expired, revoked or widened mandate, one signer speaking for another, signature twins, broken receipt chain, rewritten history under a seal, revoked bit, double undo, a passkey proof from the wrong origin or without user verification, the same order paid twice, ...) |
| [sdk/python/](sdk/python/) | reference SDK (needs `cryptography`) |
| [sdk/typescript/](sdk/typescript/) | reference SDK (no dependencies, Node 23.6+) |
| [conformance/](conformance/) | vector format and how to run it |
| [sdk/python/src/oac/](sdk/python/src/oac/) `mcp`, `browser`, `approver`, `openai_agents`, `langgraph` | the optional parts of the Python package (see the install table above) |
| [sdk/typescript/src/](sdk/typescript/src/) `mcp/`, `vercel-ai/` | the optional parts of the npm package |
| [guides/](guides/) | one short guide per part: MCP (Python, TypeScript), Gated Browser, Approver, OpenAI Agents, LangGraph, Vercel AI |
| [examples/mcp-server/](examples/mcp-server/) | a small dependency-free MCP server using the extension, and a demo with attacks that fail |

## Check everything

```
tools/check_all.sh          # PYTHON=/path/to/python to choose an interpreter
```

Both SDKs pass the same vectors, Python verifies tokens signed by TypeScript, and a differential run of about 22,600
generated inputs gives identical answers in both. The Python tests also switch off each safety check one at a time
and confirm a vector fails, so a check that quietly stops working is caught.

## Status

Spec draft 0.1, packages 0.3.0 ([changelog](CHANGELOG.md)). Not endorsed by any standards body. Feedback,
implementations and reviews are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md), and report vulnerabilities privately
as described in [SECURITY.md](SECURITY.md).

### Known gaps (help wanted)

These are open and on the list. If one matters to you, open an issue or a pull request; CONTRIBUTING.md says how a
change lands (spec, vectors, both SDKs).

| Gap | Today | Where |
|---|---|---|
| Device proofs in the MCP plug-ins | `verify_consent` / `verifyConsent` check passkey proofs, but `oac.mcp` and `open-action-consent/mcp` do not ask for them yet | spec 3.6, `spec/mcp-extension.md` 3.2 |
| Mapping to EP authorization receipts | the exact signed-byte mapping between a device proof and an EP authorization context is open; shared test vectors are proposed | `spec/mappings.md` |
| Wire version | objects still say `"oac":"0.1"` although 0.3.0 receipts and `pay` profiles are not compatible with 0.2.x | spec header |
| Occurrence scope | an order id is tracked per tool, so two different pay tools could each run the same order | spec 5.1 |
| WebAuthn backup flags | the optional check that BS is not set without BE is not done | spec 3.6 |
| SDK parity | small API differences: TypeScript exports `MemoryOccurrences` and `ActionFailed` at the top level, Python keeps them in submodules; only Python has a passkey test helper | `sdk/` |

**OAC-conformant:** an implementation that passes every case in `vectors/` may say so and link to this repository.

## License

Code, schemas and test vectors: [Apache-2.0](LICENSE). Specification text: [CC BY 4.0](LICENSE-SPEC).
