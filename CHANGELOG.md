# Changelog

## 0.6.0 (2026-11-21)

A LiteLLM integration: OAC gates MCP tool calls that pass through the LiteLLM proxy's MCP gateway, from a few lines
of `config.yaml`, for MCP servers that know nothing about OAC. No change to the spec's objects or the vectors (353,
all unchanged); the TypeScript SDK gets only the fuzzing fixes below.

- **LiteLLM guardrail** (`oac.litellm.OACGuardrail`, extra `[litellm]`, `guides/litellm.md`, binding note
  `spec/mcp-extension.md` 7.1): profiles keyed by `server/tool`; unprofiled tools, undeclared arguments and tier D
  refused; tier C refused with the Preview until the person's Consent arrives (intake endpoint, `x-oac-consent`
  header, or `accept_consent`), then run once; the arguments that will run are the ones checked and are pinned, and
  every call is refused while another `pre_mcp_call` guardrail is registered after OAC; the person comes from
  LiteLLM's key check (`user_id` or `team_id`), never the request; each attempt is closed from LiteLLM's outcome
  events with a hash-chained receipt (`ok`, `failed` when stopped before the tool ran, otherwise `unknown` for tools
  with occurrences), attempts with no outcome are closed after `ticket_timeout_s`, and `receipts_dir` keeps one chain
  per person across restarts. Tested with LiteLLM 1.108.x, end to end through the real proxy and a stdio MCP server
  whose send tool writes to a file, with planted-defect tests for the guardrail-order check and the taint default.
- `Gate.begin` and `Gate.finish` (with `Ticket`): authorize an action that runs somewhere the gate does not call, and
  close it with its receipt. `Gate.run` and `Gate.arun` now use them; their behaviour is unchanged.
- `Gate` keeps at most `max_pending` (default 1000) unanswered Previews, so an agent asking again and again cannot
  grow memory without bound.

Also in 0.6.0, robustness fixes found by new property-based fuzzing (no change to the spec, the vectors or any valid
object):

- The gate (and so the LiteLLM guardrail) refuses a person that cannot be a receipt's `sub` (1 to 256 printable ASCII
  characters) before anything runs. A tier A or B call for a person such as `"alice smith"` ran and then failed to write
  its receipt, so the action happened with no record. A LiteLLM `user_id` or `team_id` can be any string an admin set.
  TypeScript also records a tool result holding a lone surrogate by its well-formed text instead of failing the receipt.
- The LiteLLM guardrail ignores `metadata` and `headers` that are not mappings and forged non-string `oac_ticket`
  values instead of raising `AttributeError` or `TypeError`, and its no-person refusal now carries `code: malformed`
  like every other `oac_refused`. Its regexes: none; the shape regexes it relies on stay under 1 ms on 50,000-character
  hostile input.
- Key sets refuse a broken key document with `malformed`. A JWK missing a member (`{"kty": "OKP"}`), one key where a
  list was expected, or a non-object key raised `KeyError`, `ValueError` or `TypeError` (Python) and `TypeError`
  (TypeScript) instead of an `OACError`. Issuer keys come from the network (`keyset_from`), so a hostile issuer could
  crash a verifier that only expects `OACError`.
- TypeScript `canonical` refuses values JSON cannot hold, as Python already did. An array with holes was written as
  `[1,,2]` (not JSON), and a `Date`, `Map`, `Set`, typed array or boxed string became `{}` or an object of index keys,
  so `digest` and `sign` could cover something other than what the caller meant.
- Fuzzing: Hypothesis (Python) and fast-check (TypeScript) properties over strict JSON and JCS (round trip,
  idempotence, deep nesting), compact JWS on hostile and edited tokens, hostile keys, the receipt, seal and observation
  shapes, `verify_export`, `verify_chain` seals, `assess` (including payloads signed by a trusted key), the gate (an
  action is refused before it runs or gets a receipt; `accept_consent` never raises) and the LiteLLM guardrail's hooks
  (hostile tool names, arguments, metadata, headers and outcome events: an HTTP refusal with a code, never another
  exception, and nothing runs unpinned). Each must refuse with `OACError` and a known code, never another exception. A
  seeded corpus checks that Python and TypeScript JCS agree byte for byte, refusals included. They run in the normal
  test suites (100 examples each) and in a new `fuzz` CI job (1,000); `OAC_FUZZ_EXAMPLES` sets the budget.
  `hypothesis` joins the `test` extra; fast-check is a pinned dev dependency.
- CI lints the Python SDK, tests, tools and examples with ruff (from the hash lock; `ruff.toml`); the six findings
  were four unused imports and two lambdas assigned to names, fixed without a behaviour change.
- Security fix in the LiteLLM guardrail, before release: it took the person from the request (`user_api_key_user_id`
  or `user_api_key_team_id` in the hook's `data` or its `metadata`) instead of from the key LiteLLM authenticated.
  `data` is request material that a caller or an earlier guardrail can fill, so a call could act, and be approved and
  receipted, as another person. The person now comes only from the hook's `user_api_key_dict` (`user_id`, or `team_id`
  with `person_from: team_id`), and a key without one is refused (403, `code: malformed`). In LiteLLM 1.108.2 that is
  the `UserAPIKeyAuth` the MCP route's key check produced, passed through `pre_call_hook`. A planted test reads the
  person from the request again and shows a caller acting as someone else; the fuzzing now checks that receipts only
  ever name the key's person.
- `CONTRIBUTING.md` says how a change lands (pull request against `main`, required checks green); `SECURITY.md` says
  GitHub private vulnerability reporting is enabled.

## 0.5.1 (2026-11-21)

- Security fix in `assess` (spec 8.5). In 0.5.0 an observation dated more than 60 seconds before its receipt was
  dropped as stale. The executor writes the receipt's time, so an executor that dated a denial an hour ahead could make
  a real sighting of the effect look stale: the effect became `absent` and the verdict `pass`. An observation names the
  receipt's digest, so it cannot come before the receipt; one dated more than 60 seconds earlier now shows that the
  receipt's time is false, and the effect is `contradicted` (verdict `fail`). Found in a review after release. Four new
  vectors (353 in all); 0.5.0 fails them. Upgrade if you use `assess`.

## 0.5.0 (2026-11-20)

Adds completeness anchors, independent observations and a checkable coverage result. Everything is additive: objects
an older SDK made stay valid and every earlier vector gives the same result. One caution: a receipt that carries the
new `route` or `policy` field is refused by a verifier older than 0.5 (`malformed`, unknown field), so add them only
for verifiers that know them.

- Completeness (spec 8.4, new): `verify_export` / `verifyExport` checks an export against anchors, seals signed by a
  key whose issuer is not the executor, and against the verifier's own `expect` count. A chain of six cut to four still
  verifies as a chain, so the report says so: `{first, last, proven_to, status, reason}` with `status` `complete` or
  `prefix` (`no_anchor`, `unanchored_tail`, `unanchored_start`). New codes `chain_truncated` and
  `anchor_not_independent`. `verify_chain` and every earlier vector are unchanged. Raised by ceyptoslim on MCP
  SEP-2848 ([write-up](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2848#issuecomment-6903646262)).
- Observations and verdicts (spec 8.5, new): the signed observation (`typ` `oac-observation+jws`,
  `schemas/observation.schema.json`, `make_observation`) by a reader other than the executor, and `assess`, which
  returns `route`, `decision`, `effect` (`observed`, `not_observed`, `cannot_establish`, `absent`, `contradicted`,
  `duplicate`) and a `verdict`, never one merged pass. New codes `authority_mismatch` and `observer_not_independent`.
  Receipts gain optional `route` and `policy`.
- Coverage is checkable (13.2): `schemas/coverage.schema.json` and `coverage(statement, attempts)` give `covered`,
  `bypass`, `incomplete` or `not_checked` per effect, and `statement_wrong` when an effect happened on a route the
  statement does not list. The rule 3 wording points to the schema.
- Spec 6.2: the Consent item's `preview` digest is the digest of what the approver was shown (compare OpenID4VP
  `transaction_data_hashes`). Spec 12: records after the latest anchor are not protected; an executor's statement that
  it did something is a claim about itself.
- Mappings: SCITT is RFC 9943 and COSE Receipts RFC 9942; C2SP witnesses as anchor issuers; a SEP-2848 field table and
  outcome mapping (`ok` to `approved-executed`, `unknown` to `outcome-unknown`, `failed` is not `execution-error`).
  SEP-2848 is a draft with no sponsor; nothing says it is adopted.
- Independence is by key as well as by name: an anchor or observation signed with any key the verifier holds for the
  executor is refused, whatever issuer name it carries. A custodial signer run by the executor's operator is not
  independent; use a witness.
- `assess` binds the authority token more tightly: person (`sub`), executor (`aud`), time, and for a Mandate the tool.
  Seen and not seen from independent readers is `contradicted` (fail), and a look taken more than 60 s before the
  receipt does not count. `duplicate` needs `subject`.
- Inputs: a null or missing list of anchors, observations, statement rows or attempts is empty in both SDKs, and a
  wrong type is `malformed`. The TypeScript `coverage` no longer loses an effect named `__proto__`. A coverage row must
  list at least one route.
- Conformance: new ops `verify_export`, `assess`, `coverage` and `vectors/evidence.json` (110 cases), 351 in all.
- Deployment coverage (13.2): each bypass attempt records the route, whether a decision exists for that exact action,
  and whether the effect occurred as separate fields; the coverage statement lists every other route to an effect
  with the credential it holds and the control it passes through; an effect on an unlisted route breaks the whole claim; and
  `covered` means coverage of the listed routes, not of the whole system. From ceyptoslim's write-up on MCP SEP-2848.
- Release pages: each version tag now also gets its GitHub release page, made from its section in this file
  (`tools/release_notes.py`), and CI fails while the SDK version has no dated section here. The missing pages for
  0.2.1 to 0.4.1 were added on 2026-11-15 with the same tool.
- Deployment coverage (13.2), a fourth rule: keep the records. Used `jti`s, Mandate usage counts, occurrence records
  with the scope each tool had, and Receipts must survive restarts under the same atomic rules, so a paid order never
  looks new after a restart; passing the vectors does not show this. The coverage statement says where the records
  are kept, and `covered` needs records that survive a restart. Raised by the EP draft's author.

## 0.4.1 (2026-11-09)

- Occurrence scope changes: registering a tool again with a different `occurrence_scope` (adding, changing or
  removing one), or without its `occurrence`, while the store holds records in its old scope now fails
  (`ValueError` in Python, `Error` in TypeScript), in the gates and both MCP plug-ins, and leaves the old profile in
  place. Before, a paid or unresolved order could run again, which spec 5.1 already forbade. Occurrence stores gain
  an optional `has_scope` / `hasScope`; with a store that lacks it, the gates refuse every such change. After a
  restart, records kept under a tool's own name still block giving it a scope. A move between named scopes across
  a restart needs a durable store that remembers each tool's scope (README, known gaps). Reported with a reproducer
  by the EP draft's author.
- EP bridge (spec/mappings.md): an OAC device proof and an EP Class A signoff are two assertions over two different
  challenges; a pinned profile binds the OAC token digest into the EP context. Draft only, not implemented.
- Deployment coverage (spec 13.2, new): passing the vectors shows the checks hold when they are used, not that every
  route to an effect uses them. A deployment that claims OAC protects an effect names the credential that performs
  it, keeps that credential behind the executor alone, and passes a bypass check (a verified but unused Consent, then
  the effect tried by every other route). Results are `covered`, `bypass`, `incomplete` or `not_checked`. New
  security bullet "One way in" (12). Raised by ceyptoslim on MCP SEP-2848.

## 0.4.0 (2026-11-05)

Closes five of the six known gaps listed in 0.3.0. Breaking: objects now say `"oac":"0.2"`.

- Wire version: every object is labelled `"oac":"0.2"`, and `"0.1"` objects are refused, so data from SDKs up to
  0.3.0 cannot be mistaken for this draft. The spec moved to `spec/oac.md`; the old path points there. Schema ids
  are now `urn:oac:0.2:...`.
- Device proofs in the gates and MCP plug-ins: a `device` option returns the passkey check an action needs.
  `accept_consent(token, proof)` / `acceptConsent(token, proof)` takes the proof from the signer page; the MCP
  plug-ins also read `_meta["com.atlasiw/oac-device-proof"]`. Proofs are kept in `device_proofs` / `deviceProofs`.
  The same token may be posted again to bring its proof; only a well-formed proof made for that token is kept, and a
  different token still never replaces a kept one. The LangGraph, OpenAI Agents and Vercel AI adapters pass a proof
  through too.
- Occurrence scope: a profile may name `occurrence_scope` (for example one provider account). Tools with the same
  scope share one record per order, so two pay tools cannot each pay the same order. A tool without a scope keeps
  records of its own that never match a named scope. Receipts carry the scope, and chain verification compares
  occurrences within it. Do not add or change a tool's scope while it has records, unless you move them.
- WebAuthn backup flags: a proof whose BS flag is set without BE is malformed. `DeviceCheck.device_bound` refuses
  passkeys that can sync (`not_device_bound`, new error code).
- SDK parity: Python exports `Gate`, `NeedsConsent`, `ActionFailed`, `MemoryOccurrences` and `OccurrenceStore` at
  the top level, like TypeScript. TypeScript gains `passkeyProof` in `open-action-consent/testing`, like Python's
  `oac.testing.passkey_proof`.
- 11 new shared test vectors (241 in total).

Still open: the exact mapping between a device proof and an EP authorization context.

## 0.3.0 (2026-11-05)

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
