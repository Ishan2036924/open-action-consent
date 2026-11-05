# Changelog

## 0.3.0 (unreleased)

Changes from an outside review. Breaking for receipts and for `pay` tool profiles.

- Wording: low-S ES256 does not make a signature unique. The signer can make several valid tokens for one payload, so
  replay protection rests on `jti`, and every reference names the exact token bytes it saw (spec 3.3).
- Receipts: `authority.digest` is now required for consent, mandate and undo authorities. It is the `token_digest`
  of the exact token the executor verified. The executor must keep that token; the reference gate and MCP plug-ins
  keep it in `tokens` (in memory: a real executor stores it with the receipt).
- Device proofs (spec 3.6, new): `signer.kind` is described as the signer's claim. A WebAuthn passkey assertion over
  the exact Consent token can now be required, with explicit checks for challenge, origin, relying party, user
  presence and user verification. `verify_consent(..., device=DeviceCheck(...))` in Python, `device` in TypeScript.
  The MCP plug-ins do not ask for device proofs yet.
- Business occurrences (spec 5.1, new): a `pay` profile names its `occurrence` argument (an order id). The executor
  runs one occurrence at most once, refuses a fresh Consent while an earlier attempt's outcome is `unknown`
  (`occurrence_unresolved`) or after it succeeded (`duplicate_occurrence`), and `Gate.resolve` records what the
  provider says. A crash or a cancelled call also leaves the outcome unknown, never stuck. The person is not asked
  to approve an occurrence that cannot run. Occurrence ids must come from the provider or executor, not the agent.
  Receipts gain outcome `unknown` and an `occurrence` field; chain verification refuses two successful receipts for
  one occurrence (undo receipts do not count).
- 10 new error codes, 25 new shared test vectors (230 in total).
- Fix: `spec/mappings.md` pointed at the wrong section of the MCP binding for SEP-2848.

## 0.2.1 (2026-11-05)

No code or protocol changes.

- npm releases are now staged by the release workflow and go live only after a maintainer approves them (two-factor
  login); PyPI keeps publishing directly through trusted publishing.
- Package metadata now names the author.

## 0.2.0 (2026-11-05)

Same protocol (OAC 0.1). Everything now ships as one package per language, with optional parts.

- Python `open-action-consent` (PyPI): `oac.gate` (framework-neutral gate) and optional parts `oac.mcp` (official MCP
  Python SDK extension, protocol 2026-07-28), `oac.browser` (Gated Browser: final clicks only with a signed yes on that
  exact page, page-change refusal, CAPTCHA hand-off, no secrets typed, private-address guard; command
  `oac-gated-browser`), `oac.approver` (self-hostable approval page; non-extractable WebCrypto key in the browser signs
  the Consent), `oac.openai_agents`, `oac.langgraph`. Install with `[mcp]`, `[browser]`, `[approver]`,
  `[openai-agents]`, `[langgraph]` or `[all]`.
- TypeScript `open-action-consent` (npm, built with TypeScript 7): `Gate`, `open-action-consent/mcp` (MCP SDK v2 tool
  wrapper) and `open-action-consent/vercel-ai` (AI SDK 7 adapter).
- In every framework adapter, the framework's own approval alone runs nothing without the person's signed Consent.
- `oac.mcp`: optional `inspect` hook seals evidence (page digests) into the Preview and refuses if it changed.
- Release workflow with trusted publishing (no stored tokens).

## 0.1.0 (2026-11-04)

First public draft.

- Spec: Action Profile, Preview, Consent, Mandate, Receipt, Undo; tiers A–D; MCP 2026-07-28 binding built on
  SEP-2848 and SEP-2793; mappings to AP2, Verifiable Intent, ACP, UCP, A2A and the IETF receipt drafts; dispute profile.
- Key discovery (`/.well-known/oac-issuer`), status lists (W3C Bitstring Status List encoding) and chain seals.
- Python and TypeScript reference SDKs, 205 conformance vectors, JSON schemas, an example MCP server and demo.
- Hardened after an independent security and cross-language review: every argument declared and shown, bare
  recipient addresses, issuer-bound keys, revocation, host-reported taint, atomic nonces, single undo, low-S ES256,
  strict JSON and gzip parsing.
