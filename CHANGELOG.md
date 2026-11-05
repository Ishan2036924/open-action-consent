# Changelog

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
