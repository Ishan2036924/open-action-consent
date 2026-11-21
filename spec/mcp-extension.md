# OAC over MCP (extension draft, for MCP 2026-07-28)

Status: draft input to the MCP extensions track. Written to sit on top of two open proposals rather than compete with
them: SEP-2848 (asynchronous tool approval) and SEP-2793 (tool risk metadata, including `reversibility`). Both were
open and unsponsored when this was written (2026-11-04).

Extension identifier: `com.atlasiw/oac` (provisional; it uses a domain the authors control, as MCP's naming rules
require, and would move to a neutral prefix if the extension is adopted). `_meta` keys below use the same prefix.

## 1. Negotiation

MCP 2026-07-28 has no handshake: capabilities travel on every request. A client that supports OAC declares it in
each request's `_meta`:

```json
{"_meta": {
  "io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientCapabilities": {
    "elicitation": {"url": {}},
    "extensions": {"com.atlasiw/oac": {"version": "0.2"}}
  }
}}
```

A server advertises it in `server/discover` → `capabilities.extensions`:

```json
{"resultType": "complete", "supportedVersions": ["2026-07-28"],
 "capabilities": {"tools": {}, "extensions": {"com.atlasiw/oac": {"version": "0.2", "executor": "https://shop.example/oac"}}}}
```

`executor` is the value Consents must carry in `aud`.

## 2. Action Profiles on tools

Each tool in `tools/list` carries its Action Profile:

```json
{"name": "book_table", "description": "Book a table", "inputSchema": {"type": "object"},
 "_meta": {"com.atlasiw/oac-profile": {"oac": "0.2", "type": "action-profile", "tool": "book_table",
   "effect": "write", "undo": {"kind": "compensate", "window_s": 86400}, "tier_floor": "A",
   "binds": {"payee": "restaurant", "when": "time", "count": "party"}}}}
```

The profile is the author's claim. Clients and executors MUST NOT lower a tier because of it (spec section 5). MCP's
own `annotations` (`readOnlyHint`, `destructiveHint`, ...) stay as they are; if SEP-2793 lands, its `reversibility`
maps as `auto` → `native`, `manual` → `compensate`, `none` → `none`.

## 3. A tier C call

### 3.1 First call: the server asks for consent

The executor computes the tier (spec section 4). For tier C with no Mandate that covers the call, it builds the
Preview and answers with an MCP `input_required` result carrying a URL-mode elicitation. The URL opens the person's
signer (a page the model cannot read or drive), which shows the Preview and signs.

```json
{"jsonrpc": "2.0", "id": 1, "result": {
  "resultType": "input_required",
  "inputRequests": {
    "oac_consent": {"method": "elicitation/create", "params": {
      "mode": "url",
      "url": "https://signer.example/oac/consent?r=pv_3f9a",
      "message": "Approve: Book Nobu Boston, Fri 6 Nov 7:30 pm, 2 people. Free cancellation until 24 h before."}}},
  "requestState": "<integrity-protected blob>",
  "_meta": {"com.atlasiw/oac-preview": {"oac": "0.2", "type": "preview", "...": "..."}}
}}
```

- `requestState` MUST be integrity-protected (HMAC or AEAD) and SHOULD hold the authenticated principal, the preview
  digest, the action digest and a short expiry, as MCP's multi round-trip rules ask.
- The Preview in `_meta` lets the client show the same fields; the signer's page is what the person approves.
- The URL MUST NOT carry personal data or a pre-authenticated session (MCP's URL-mode rules).
- How the signer hands the Consent to the executor (a server-to-server post, or the executor fetching it by preview
  id) is between them; OAC 0.2 does not fix that endpoint.

### 3.2 Retry: the server verifies and runs

The client retries the same call with the elicitation result and the echoed state:

```json
{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
  "name": "book_table", "arguments": {"restaurant": "Nobu Boston", "time": "2026-11-06T19:30-05:00", "party": 2},
  "inputResponses": {"oac_consent": {"action": "accept"}},
  "requestState": "<the same blob>",
  "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "...": "..."}}}
```

`accept` only means the person opened the page. The server MUST find the signed Consent for this preview, run the
checks of spec 6.3 against the arguments in this retry (with `sub` from its own authentication of the caller), and
only then run the tool. A Consent arriving from the signer MUST be verified when it arrives, and a stored valid
Consent MUST NOT be replaced by a later post, so a stray or hostile post cannot block the person's approval. If no valid Consent exists yet,
it answers with another `input_required` result; if the person declined, with a tool error and no action.

A client that is itself the person's signer (for example a wallet app holding a device key the model cannot reach)
MAY attach the token directly: `_meta["com.atlasiw/oac-consent"]: "<compact JWS>"`. The server verifies it the same
way; which signers it trusts is its own policy (spec 3.3).

When the server requires a passkey (spec 3.6), the device proof travels with the Consent: the signer page posts it
together with the token, or the client attaches `_meta["com.atlasiw/oac-device-proof"]: {...}`. Without a valid proof
the server refuses with the code from spec 3.6 and runs nothing. A well-formed proof posted with the token, made for
that token, wins over one in `_meta`; anything else posted with it is ignored. The server keeps the proof with the token, next to the receipt.

### 3.3 The result carries the receipt

```json
{"jsonrpc": "2.0", "id": 2, "result": {
  "resultType": "complete",
  "content": [{"type": "text", "text": "Booked. Confirmation NB-2231."}],
  "_meta": {"com.atlasiw/oac-receipt": "<compact JWS, typ oac-receipt+jws>"}}}
```

Tier B results carry a receipt too, with the native undo token. Tier A results MAY.

### 3.4 Occurrences and unclear outcomes

For a tool whose profile names an `occurrence` (spec 5.1), the server claims the occurrence before it verifies the
Consent, and refuses with `occurrence_unresolved` or `duplicate_occurrence` without using up the Consent. A tool error
is recorded as outcome `unknown`, because a timed-out payment may still have gone through, unless the tool marks
its result `_meta["com.atlasiw/oac-outcome"]: "failed"` to say it surely did not happen. The receipt carries the
outcome. An `unknown` occurrence runs again only after the server has asked the provider and recorded `failed`.

## 4. Mandates and taint

An agent holding a Mandate attaches it to the call: `_meta["com.atlasiw/oac-mandate"]: "<compact JWS>"`, or the
executor looks up Mandates it holds for the authenticated caller. The executor runs spec 7.3 and counts the use in
the same transaction as the action. Any failure falls back to 3.1 (ask the person); `tainted` always does.

Taint (spec section 4) is decided by the host application that runs the agent and sees what entered the run, never
by the model. The host states it on each call:

```json
{"_meta": {"com.atlasiw/oac-run": {"run": "<host run id>", "tainted": false}}}
```

The executor MAY trust this only from a host it has authenticated and reviewed (a first-party app, an MCP client it
registered); it MUST treat a missing, unauthenticated or unknown statement as `tainted: true`. A model can write tool
arguments but not `_meta`, and the executor never reads taint from arguments. The executor numbers runs for
`per_run` limits itself (for example inside `requestState`); the host's run id is only a hint.

## 5. Undo

The server exposes one tool, `oac_undo`, whose arguments are `{"request": "<undo JWS>", "receipt": "<receipt JWS>"}`.
Its own profile is `effect: write`, `undo: none`, so it is tier C; the signed undo request is its authority in place of
a Consent (receipt `authority.kind: "undo"`). The executor runs spec 8.3, keeps the set of receipts it has undone,
and returns the undo receipt in `_meta["com.atlasiw/oac-receipt"]`. A `compensate` undo is a call to the compensating
tool (for example `cancel_booking` with `undoes: <receipt digest>`) that goes through 3.1 like any tier C call; its
undo request names that Consent.

## 6. Without the extension

If the client does not declare `com.atlasiw/oac` (or does not support URL elicitation), the server MUST NOT run a
tier C or D tool. It MUST either return `MissingRequiredClientCapability` (-32021) listing the missing capability, or
obtain consent through a channel of its own (its own app) and only then run. Tier A and B tools work unchanged; tier B
still keeps its receipt and undo for the person, even if the client never sees them.

## 7. Reference plug-ins

`oac.mcp` in the Python package (official Python SDK, which has an extension interceptor and seals `requestState`) and
`open-action-consent/mcp` in the npm package (official TypeScript SDK v2, which has neither, so the plug-in wraps each tool and signs
its own state) implement this binding and are tested end to end through each SDK's in-memory client. Both handle occurrences (3.4)
and device proofs: the server's `device` option returns the passkey check an action needs (or none), and the plug-in
fills in the proof that came with the Consent.

### 7.1 Gateways

A gateway in front of MCP servers that do not speak OAC (for example `oac.litellm` in the LiteLLM proxy) is the
executor for the calls it forwards, and obtains consent through a channel of its own (section 6). It decides on the
arguments that will reach the server, after any rewrite by components before it, and nothing after it may change
them. A tool's profile is keyed by server and tool name together (`server/tool`), so the same tool name on two
servers is two tools. The person comes from the gateway's own authentication of the caller, never from the request.
A call it refuses runs nothing; for a tier C call without a Consent the refusal carries the Preview, and the same call
retried after a valid Consent has arrived runs once. A call stopped after approval but before the server could run
it gets a receipt with outcome `failed`.

## 8. Relation to SEP-2848

Status as read on 2026-11-20: SEP-2848 is a draft pull request with no sponsor, and MCP's maintainers asked that it go
through the Authorization Interest Group first. Nothing here says it, or any part of it, has been adopted.

SEP-2848 turns a denied call into a Task that resolves when someone approves out of band. The server keeps an immutable
binding of the call (tool name, complete arguments, and optionally a digest over a canonical serialization), and the
approval is an input to a new decision, never a standing grant. The approval protocol stays on the server's side and
never crosses the MCP wire. OAC supplies what the SEP leaves open: the approval as a signed, portable object bound to
a Preview, and a receipt afterwards. If SEP-2848 is adopted, section 3 can use its task handle instead of
`input_required`, and an OAC Consent becomes the approval material its server-side binding stores. The Consent stays
off the wire; a client that carries `_meta["com.atlasiw/oac-consent"]` (3.2) is an optional path for clients that sign.

Outcome mapping. The SEP's disposition in the Task result `_meta` and the OAC receipt's `outcome` (spec 8.1) answer
nearly the same question, with one exception:

| OAC `outcome` | SEP-2848 disposition | Note |
|---|---|---|
| `ok` | `approved-executed` | |
| `unknown` | `outcome-unknown` | |
| `failed` | not `execution-error` | `execution-error` says a side effect may have occurred; OAC `failed` says it surely did not (3.4). Keep both fields. |
| no receipt | `denied-not-executed` | OAC receipts are one per executed action, so a denial has no receipt today |

The receipt travels in the result `_meta` (3.3). The SEP's own limitation, that a deployment needs "a durable consumer
or an effect that is independently auditable", has no protocol object in the SEP. The OAC pieces that could fill it are
the receipt chain with an anchor (spec 8.4) and an observation by a reader other than the executor (spec 8.5); both are
optional evidence, not new wire members. ceyptoslim's write-up in the SEP thread
([comment](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2848#issuecomment-6903646262)) is the origin of 8.4, 8.5 and the recording rule of 13.2.
