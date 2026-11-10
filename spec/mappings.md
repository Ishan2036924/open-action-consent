# How OAC maps to other work

Informative. Facts as read on 2026-11-04 from the linked pages; these projects move fast, so check the source before
relying on a row.

## Payment and commerce

| Other | Its object | OAC counterpart | How they meet |
|---|---|---|---|
| AP2 v0.2 ([ap2-protocol.org](https://ap2-protocol.org/), Apache-2.0) | Checkout and Payment mandates, each open (constraints, agent key) then closed (bound to the checkout by hash); user-signed SD-JWT | Mandate ≈ open mandate; Consent with `payment` ≈ closed mandate | `payment.rail = "ap2"`, `payment.ref` = the mandate id. OAC adds the Preview, the undo kind and the receipt chain; AP2 stays the payment proof |
| Mastercard Verifiable Intent draft 0.1 ([repo](https://github.com/agent-intent/verifiable-intent), Apache-2.0) | L2 user-signed intent: immediate (final values) or autonomous (constraints); disputes out of scope | Consent ≈ L2 immediate; Mandate ≈ L2 autonomous | `payment.rail = "vi"`. OAC's dispute profile covers what VI leaves out |
| Stripe Link agent wallet ([docs](https://docs.stripe.com/agentic-commerce/link-cli/use-link-wallet-pay-online)) | spend request the person approves in Link; one-time credential to the agent | Consent `payment` points to the spend request | `payment.rail = "stripe_link"`, `ref` = spend request id; the credential goes to the executor, never the model (spec 9) |
| Stripe Shared Payment Token ([docs](https://docs.stripe.com/agentic-commerce/concepts/shared-payment-tokens)) | scoped token with amount and expiry limits | the rail's second lock (spec 9 rule 4) | limits must equal the signed Preview |
| ACP ([repo](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol), Apache-2.0) | merchant checkout sessions, order webhooks | Receipt `payment.order` | refunds and cancels use ACP's order flow; OAC records them as compensating actions |
| UCP ([ucp.dev](https://ucp.dev)) | catalog, cart, checkout, orders; AP2 for payment | same as ACP | same as ACP |
| x402 v2 ([repo](https://github.com/x402-foundation/x402), Apache-2.0) | per-request payment payload and settle response | Consent `payment.rail = "other"` | x402 has no user consent object; OAC can supply one |

## Agents and tools

| Other | Its object | OAC counterpart | How they meet |
|---|---|---|---|
| MCP 2026-07-28 ([spec](https://modelcontextprotocol.io/specification/2026-07-28)) | URL-mode elicitation (accept/decline/cancel, unsigned); tool annotations (hints) | Consent (signed); Action Profile | `mcp-extension.md` |
| MCP SEP-2848 ([PR](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2848)) | async approval via Tasks; args digest; unsigned | Consent as the approval evidence | `mcp-extension.md` section 8 |
| MCP SEP-2793 ([PR](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2793)) | `reversibility` auto/manual/none, `approvalRecommendation` | `undo.kind` native/compensate/none; tiers | one to one for reversibility; OAC tiers are computed, not recommended |
| A2A v1.0 ([spec](https://a2a-protocol.org/latest/specification/), Apache-2.0) | `INPUT_REQUIRED` task state; extensions; JWS over JCS for Agent Cards | Preview / Consent | carry the Preview when a task is `INPUT_REQUIRED` for approval, and the Consent and Receipt as extension data; same JWS + JCS building blocks |
| OpenAI Agents SDK (`needs_approval`), LangGraph (`interrupt`) | in-process approvals and interrupts, unsigned | Consent | `oac.openai_agents`, `oac.langgraph`: the pause carries the Preview; the tool runs only with a verified Consent |
| Vercel AI SDK 7 (`toolApproval`, `experimental_toolApprovalSecret`) | approval request/response; the server can HMAC-sign approval requests | Consent | `open-action-consent/vercel-ai`; the HMAC stops forged requests, OAC adds the person's own signature over what they saw and a receipt |

## Receipts, consent records, identity

| Other | Its object | OAC counterpart | How they meet |
|---|---|---|---|
| IETF draft-schrock-ep-authorization-receipts-13 ([datatracker](https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/)) | authorization context over a JCS action; WebAuthn challenge = context hash | Consent plus a device proof (spec 3.6) | the proof is a plain WebAuthn assertion whose challenge is SHA-256 of the exact Consent token; `signer.kind = "device"` alone is only the signer's claim. An OAC assertion cannot double as an EP one; the bridge is the pinned profile below |
| IETF agent audit-trail and SCITT agent drafts | hash-chained logs, COSE records | Receipt chain | export receipts into those logs; OAC does not need its own log format |
| Acta, delegation and counter-sign receipt drafts | signed receipts | Receipt | export target |
| ISO/IEC TS 27560 | consent record for personal-data processing | Consent / Mandate | a Mandate can be summarized as a 27560 record for privacy records |
| W3C Bitstring Status List ([REC, 2025-05-15](https://www.w3.org/TR/vc-bitstring-status-list/)) | `encodedList` (GZIP + multibase base64url), `statusListIndex` | status list `encoded_list`, Mandate `status.index` | same bitstring encoding and bit order; an OAC list can be re-wrapped as a BitstringStatusListCredential |
| RFC 8414 (OAuth server metadata) | `/.well-known/oauth-authorization-server` with path insertion | `/.well-known/oac-issuer` | same location rule; OAC lists keys inline |
| IETF SCITT | transparency log of signed statements | seal + receipt | register seals as signed statements for third-party proof of time |
| Web Bot Auth (IETF WG) | the agent's HTTP message signatures to websites | executor key | the executor may publish one key directory for both |
| RFC 9396 RAR, OpenID CIBA | typed authorization details; out-of-band approval with a short binding message | Preview fields; URL-mode consent | an authorization server can render a Preview and return a Consent instead of only a token |

### EP Class A bridge (draft, not implemented or tested)

One WebAuthn assertion signs one challenge, so an OAC device proof (challenge: the hash of the exact Consent token)
and an EP Class A signoff (challenge: the hash of the complete JCS Authorization Context) are two assertions. Neither
stands in for the other. A pinned native-binding profile, proposed by the EP draft's author:

1. Verify the OAC objects natively (Consent, Preview binding, device proof per 3.6) and keep their exact token bytes.
2. Build the EP Authorization Context so that it carries the OAC Consent's `token_digest`, binding the two.
3. Obtain the EP assertion over the hash of that complete JCS context, with EP's own checks.

Which EP field carries the digest, and which inputs each side must trust, follow the EP draft and are still being
settled with its author. Shared vectors for the bridge come with the first implementation.
