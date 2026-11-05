# Changelog

## Unreleased

- `integrations/mcp-python`: OAC as an extension for the official MCP Python SDK (`mcp` 2.3, protocol 2026-07-28).
- `integrations/mcp-typescript`: OAC tool wrapper for the official MCP TypeScript SDK v2 (2.4).
- `integrations/gated-browser`: an MCP browser that stops before every final click; page-change detection, CAPTCHA
  hand-off, no secrets typed, private-address guard on every request.
- `integrations/approver`: a self-hostable approval page; non-extractable WebCrypto key in the browser signs the
  Consent (device signer); enrolment by one-time code; issuer metadata for key discovery.
- `oac.gate` / `Gate` (Python and TypeScript): framework-neutral executor gate shared by the adapters.
- Adapters: OpenAI Agents SDK (`oac_tool`), LangGraph (`gated` with `interrupt`), Vercel AI SDK (`withOAC`); in
  each, the framework's own approval alone runs nothing without the person's signed Consent.
- `oac-mcp`: optional `inspect` hook seals evidence (page digests) into the Preview and refuses if it changed.

## 0.1.0 (2026-11-04)

First public draft.

- Spec: Action Profile, Preview, Consent, Mandate, Receipt, Undo; tiers A–D; MCP 2026-07-28 binding built on
  SEP-2848 and SEP-2793; mappings to AP2, Verifiable Intent, ACP, UCP, A2A and the IETF receipt drafts; dispute profile.
- Key discovery (`/.well-known/oac-issuer`), status lists (W3C Bitstring Status List encoding) and chain seals.
- Python and TypeScript reference SDKs, 205 conformance vectors, JSON schemas, an example MCP server and demo.
- Hardened after an independent security and cross-language review: every argument declared and shown, bare
  recipient addresses, issuer-bound keys, revocation, host-reported taint, atomic nonces, single undo, low-S ES256,
  strict JSON and gzip parsing.
