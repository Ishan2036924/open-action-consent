# Open Action Consent (OAC), draft 0.2

Status: draft. Not endorsed by any standards body. Licensed under CC-BY-4.0 (see LICENSE-SPEC).

Objects in this draft say `"oac":"0.2"`. Objects labelled `"0.1"` came from earlier drafts (SDKs up to 0.3.0) and
are refused (`malformed`): receipts there may lack `authority.digest`, and `pay` profiles may lack an `occurrence`.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119 and RFC 8174 when,
and only when, they appear in all capitals.

## 1. What OAC is for

An AI agent increasingly acts for a person: it sends mail, books tables, deletes files, pays. Today the person's "yes"
is usually a button whose meaning no one else can check. OAC makes that yes portable and verifiable:

1. Before an action that matters, the **executor** (the tool side, never the model) builds a **Preview** of exactly
   what will happen, with every structured field bound to the call's own arguments.
2. The person signs a **Consent** over the digest of that Preview, or a **Mandate** they signed earlier covers it.
3. The executor runs the action only if the signature, the binding and the limits all check out.
4. The executor signs a **Receipt**, chained to the previous one, that says what ran and how to **Undo** it.

OAC does not move money, identify bots, define checkout, or set liability. It sits beside the protocols that do
(section 11) and points to them.

## 2. Roles

| Role | Does | Holds |
|---|---|---|
| Person (`sub`) | decides | nothing in the protocol; their signer holds the key |
| Signer (`iss` of Consent, Mandate, Undo) | signs for the person, only after it has proven the person is present | the user key |
| Agent / holder | proposes actions; may hold a Mandate | no key that can sign for the person |
| Executor (`aud`) | builds Previews, verifies, runs, signs Receipts | the executor key |
| Verifier | anyone checking objects later (the person, an auditor, a dispute team) | public keys only |

A model MUST NOT hold, use, or be able to cause use of the user key. The executor MUST NOT accept a Consent or Mandate
that the agent could have produced.

## 3. Encoding

### 3.1 JSON

All objects are JSON. Numbers MUST be integers between -(2^53 - 1) and 2^53 - 1: money is in minor units with an ISO
4217 `currency`; times are unix seconds. Parsers MUST refuse duplicate object keys, fractions, exponents, NaN,
Infinity, a byte-order mark, invalid Unicode (including lone surrogates, in keys too) and nesting deeper than 64
arrays or objects (`malformed`). Implementations MUST parse everything they receive (tokens, Previews, actions,
profiles) with such a strict parser; a lenient parser can read `2.0` as `2` and so judge a different value than the
signer did.

### 3.2 Canonical form and digests

The canonical form of a value is RFC 8785 (JCS). With integers only, it is: no whitespace; object keys sorted by their
UTF-16 code units; strings escaped as ECMAScript `JSON.stringify` does; integers in plain decimal. Strings MUST be
valid Unicode.

A **digest** is `"sha-256:" + base64url(SHA-256(bytes))`, unpadded. `digest(value)` hashes the canonical bytes of a
value. `token_digest(token)` hashes the ASCII bytes of a compact JWS.

The **action** is `{"tool": <name>, "args": <object>}` and its digest is `digest(action)`.

### 3.3 Signed objects

Consent, Mandate, Receipt and Undo request are JWS compact serializations (RFC 7515):

- the token is ASCII; the protected header is exactly `{"alg", "kid", "typ"}`, canonical;
- `alg` is `EdDSA` (Ed25519, RFC 8037) or `ES256` (P-256, signature as raw r||s with s at most n/2);
- `kid` is the RFC 7638 thumbprint of the signing key's public JWK;
- `typ` is `oac-consent+jws`, `oac-mandate+jws`, `oac-receipt+jws` or `oac-undo+jws`, and a verifier MUST check
  it, so that no object can pass for another;
- the payload is the canonical bytes of the object.

A verifier MUST refuse a token whose header or payload is not byte-for-byte the canonical form of what it parses to
(`not_canonical`). Base64url MUST be unpadded with zero pad bits.

**Signatures are not unique.** Requiring s at most n/2 ("low-S") stops anyone else from turning a valid ES256 token
into a second valid token for the same payload. It does not stop the signer: ECDSA signing is randomized, so signing
the same payload twice gives two valid tokens with different `token_digest`s. Replay protection therefore rests on
`jti`, never on the signature. Anything that refers to a signed object (a receipt's `authority`, `prev`, `undoes`, a
seal's `head`, a device proof's `consent`) names the exact token bytes received, by their `token_digest`, and an
implementation that may need to show that object later MUST keep those bytes, not a re-serialized or re-signed copy.

Envelope checks, in order: three parts, ASCII, base64url (`malformed`); header canonical (`not_canonical`) and
exactly those members (`malformed`); `typ` (`bad_type`); `alg` (`bad_alg`); `kid` known (`unknown_key`); key type
matches `alg` (`bad_alg`); signature (`bad_signature`); payload canonical object (`not_canonical`, `malformed`);
the payload's `iss` is the issuer the key belongs to (`wrong_issuer`).

Key sets: a verifier holds, from a source it trusts, public keys **grouped by issuer**: each key belongs to exactly
one issuer (a person's signer, or one executor). A token signed by a key MUST name that key's issuer as `iss`, so a
second trusted signer can never sign in the first one's name. Section 3.5 says where issuers publish their keys.

### 3.4 Signer kinds

`signer.kind` is the signer's own statement of how it proved the person was present:

| kind | Meaning |
|---|---|
| `custodial` | a signer service holds the key and signs only after a live, recent sign-in of the person |
| `device` | the signing key is held on the person's device |

The statement is covered by the signer's signature, so it cannot be changed in transit, but it is a claim: it is
worth exactly as much as the verifier's trust in that signer. It is not a WebAuthn assertion, does not show that the
person unlocked the device, and is not an authorization context of another protocol. A verifier that needs proof it
can check for itself requires a device proof (3.6).

### 3.5 Issuer metadata (key discovery)

An issuer that wants to be found is identified by `https://host[:port][/path]`: lowercase ASCII host, path segments of
unreserved characters, no `.` or `..` segments, no query, fragment or credentials. It publishes an issuer metadata
document (`schemas/issuer-metadata.schema.json`) at

```
https://host[:port]/.well-known/oac-issuer[/path]
```

(the well-known form RFC 8414 uses for OAuth servers; a trailing slash on the issuer is dropped). The document's
`issuer` MUST equal the issuer exactly (`wrong_issuer`); `keys` holds public JWKs only (a private member is
`malformed`); `status_lists` MAY list the ids of its status lists (7.5). Implementations MUST compute the location
by matching the text above, not with a URL parser that might normalize it. A fetcher MUST use HTTPS, MUST NOT
follow redirects, and SHOULD cap the size (64 KB in the SDKs) and time. A verifier MAY cache the document and MUST
treat a key that disappears from it as no longer trusted.

### 3.6 Device proofs (WebAuthn)

A **device proof** is a WebAuthn assertion (W3C Web Authentication Level 3) made by the person's passkey over one
exact Consent token. It travels next to the Consent (in MCP, in `_meta`; see `mcp-extension.md`), keeps the Consent in
its native OAC form, and maps byte for byte to a WebAuthn ceremony. Schema: `schemas/device-proof.schema.json`.

```json
{"oac":"0.2","type":"device-proof","consent":"sha-256:<token_digest of the Consent>","credential":"<credential id>",
 "authenticator_data":"<base64url>","client_data_json":"<base64url>","signature":"<base64url, DER>"}
```

Signed bytes, exactly as WebAuthn defines them: `authenticator_data || SHA-256(client_data_json)`, signed with the
credential's private key. The client data's `challenge` is `base64url(SHA-256(consent token ASCII bytes))`, unpadded:
the same hash as the Consent's `token_digest`, without the `sha-256:` prefix. OAC 0.2 accepts ES256 credentials
(COSE algorithm -7, P-256); the executor stores each registered credential's public key as a JWK with its owner.

An executor that requires a device proof for a Consent (by policy, for example for any payment) knows the person's
registered credentials, its relying party id and the origins its approval page is served from. It checks, in order:

1. a proof is present (`device_proof_missing`); its fields (`malformed`);
2. `consent` equals `token_digest` of the Consent being verified (`device_proof_mismatch`);
3. the credential is one of this person's (`unknown_credential`);
4. the signature over the signed bytes, with that credential's key (`bad_signature`); authenticator data shorter than
   37 bytes is `malformed`;
5. the client data parses as a JSON object whose `type` is `webauthn.get` (`malformed`);
6. `challenge` is the Consent's challenge (`challenge_mismatch`);
7. `origin` is one of the executor's origins and `crossOrigin` is not `true` (`wrong_origin`);
8. the first 32 bytes of the authenticator data equal SHA-256 of the relying party id (`rp_mismatch`);
9. the UP flag (bit 0) is set (`user_not_present`); the UV flag (bit 2) is set (`user_not_verified`);
10. the BS flag (bit 4, backed up) is not set without the BE flag (bit 3, backup eligible) (`malformed`). An executor
    that wants a passkey bound to one device (for example for large payments) refuses a set BE flag
    (`not_device_bound`); by default synced passkeys are accepted.

These checks are step 7 of 6.3, so a refused proof does not use up the Consent's `jti`. The signature counter is not
checked in 0.2; an executor MAY check it as WebAuthn describes.

## 4. Tiers

Every action gets one tier:

| Tier | Meaning | Needs |
|---|---|---|
| A | read-only, or no effect outside the person's own data | nothing; a Receipt is optional |
| B | a write the executor can take back itself (`native` undo) | runs; MUST produce a Receipt with an Undo token |
| C | sends, pays, deletes shared data, or cannot be undone in one step | a Consent bound to its Preview, or a Mandate that covers it |
| D | forbidden | MUST be refused, whatever is presented |

The tier is computed, never declared by the caller:

```
implied(profile) = A if effect is read
                 = B if effect is write or delete and undo.kind is native
                 = C otherwise
tier = max(implied(profile), profile.tier_floor, executor policy floor,
           C if the run is tainted and effect is not read,
           any hint)
```

Tier names are exactly `A`, `B`, `C`, `D`; anything else is `malformed`. A hint (for example from a model) MAY raise
the tier; because the result is a maximum, it can never lower it.

**Taint.** A run is tainted when text from outside the person's own words or data (a web page, an email, a shared
document, an unreviewed tool's output) has entered it. Taint MUST be decided by the host runtime that sees what
entered the run, never by the model or the agent, which an injection can steer. An executor that cannot get a
taint decision from a host it trusts MUST treat the run as tainted. In practice: a Mandate is usable only where the
host vouches for the run (section 7.2); everywhere else the person is asked.

## 5. Action Profile

Published by a tool's author (in MCP, in the tool's `_meta`; section 10). Schema: `schemas/action-profile.schema.json`.

```json
{"oac":"0.2","type":"action-profile","tool":"send_email","effect":"send",
 "undo":{"kind":"none","window_s":0},"tier_floor":"A",
 "binds":{"to":"to","title":"subject"},"other_args":["body"]}
```

- `effect`: `read`, `write`, `send`, `pay` or `delete`.
- `undo.kind`: `native` (the executor restores the prior state), `compensate` (a new action puts it right but cannot
  hide that it happened: a cancel, a refund), `none` (cannot be taken back). `none` has `window_s` 0; the others at
  least 60. A `read` declares `none`.
- `binds` maps Preview fields to argument names. Preview fields are: `title`, `when`, `payee` (display text),
  `to` (a list of single bare addresses), `amount_minor`, `currency`, `site`, `count`.
- `other_args` lists every other argument the tool takes. The Preview shows them unchanged in `details`.
- `occurrence` names the argument that identifies the business occurrence: the order, payment or booking the action
  is about (5.1). Required for `pay`; it MUST be a declared argument, and its value in every action MUST match
  `[A-Za-z0-9_.:-]{1,128}` (`malformed`).
- `occurrence_scope` (optional, same pattern) names where those ids are unique, such as one provider account
  (`stripe:acct_1`). It needs `occurrence`. Without it, the tool has a scope of its own, which never matches a named
  scope even when the two are spelled alike.

Rules:

1. **Every argument is declared.** An action whose arguments include a name that is neither bound nor in
   `other_args` MUST be refused (`undeclared_argument`). So an agent cannot add a `bcc` the person never sees.
2. No argument is declared twice.
3. A `pay` tool MUST bind `amount_minor`, `currency` and `payee`, and its actions MUST carry all three. A `send`
   tool MUST bind `to`, and its actions MUST carry it. A send tool carries every recipient in that one argument.
4. Bound argument values MUST be valid field values (`malformed`): `to` entries are one ASCII `local@domain` each
   (no display names, no lists, no line breaks); display text has no control, bidi-override or zero-width
   characters.

### 5.1 Business occurrences

A Consent is single-use, but a person can approve the same thing twice: a payment times out, the agent asks again, the
person says yes again. The second Consent has a new `jti`, so the nonce check does not stop it, and the first attempt
may have gone through. The occurrence id closes this gap. For a tool whose profile names an `occurrence`, the executor
keeps one record per person, occurrence scope and occurrence value, with the state of its latest attempt: `running`,
`ok`, `failed` or `unknown`. Tools whose profiles name the same `occurrence_scope` share these records, so an order
paid through one tool cannot be paid again through another; a tool without a scope has records of its own. An
executor MUST NOT add or change a tool's `occurrence_scope` while that tool has records, unless it moves them to the
new scope; otherwise an order already paid, or still `unknown`, would look new.

1. Before it runs the action (for tier C, before it verifies the Consent, so a refusal does not use up the `jti`), the
   executor claims the record atomically: new or `failed` becomes `running`; `ok` is refused
   (`duplicate_occurrence`); `running` or `unknown` is refused (`occurrence_unresolved`). If the Consent is then
   refused, the claim is dropped. An executor SHOULD make the same check before it asks the person, so nobody approves
   something that cannot run.
2. The executor passes the occurrence value to the provider as its idempotency key (Stripe's `Idempotency-Key`, an
   order reference), so the provider can also refuse a second attempt.
3. When the action ends: success records `ok`; a failure the tool is sure of records `failed`; anything else (a
   timeout, a crash, an unclear error) records `unknown`. The receipt carries the same outcome.
4. An `unknown` attempt is resolved only by asking the provider, by the same occurrence value, what happened. The
   executor then records `ok` or `failed`. Only after `failed` may a fresh Consent run the occurrence again. A
   `running` record left behind by a crash or a cancelled call is treated as `unknown`.
5. The occurrence value MUST be one the provider or the executor issued for this order (a checkout, order or booking
   id), never one the agent made up. An executor MUST refuse a value it cannot confirm with the provider
   (`malformed`). Otherwise an agent could retry under a new id and the record would not catch it.

A compensation (a refund, a cancel) is a separate action with its own Preview and Consent (8.3), never a retry.

Profiles are claims by the tool's author. An executor MUST treat a profile from an unreviewed source as untrusted
and SHOULD apply a policy floor of C to its writes.

## 6. Preview and Consent

### 6.1 Preview

Schema: `schemas/preview.schema.json`.

```json
{"oac":"0.2","type":"preview","id":"pv_send_email","executor":"https://mail.example/oac","sub":"person:7f3a",
 "tool":"send_email","action":"sha-256:...","summary":"Email sam@example.com: Lunch Friday?",
 "fields":{"to":["sam@example.com"],"title":"Lunch Friday?"},
 "details":{"body":"Does 1 pm work?"},
 "undo":{"kind":"none","window_s":0},"iat":1793836770,"exp":1793837370}
```

Rules:

1. The executor MUST build the Preview from the action it will run. `fields` MUST contain exactly the bound
   arguments that are present, each equal to its argument; `details` MUST contain exactly the `other_args` that are
   present, unchanged (omitted when empty); `undo` MUST equal the profile's.
2. `summary` is free text for humans, with no control, bidi-override or zero-width characters. It SHOULD be produced
   by executor code, not a model, and MUST NOT contradict `fields`. Verifiers cannot check it; that is why `fields`
   and `details` exist.
3. `exp` is after `iat` and at most 900 seconds later.
4. `evidence` MAY carry digests of a screenshot and of the page DOM the person saw (browser agents).
5. The client MUST show the person `summary`, every field, every detail, the undo kind, and `cancel_policy` when
   present, escaping anything it renders. An undo kind of `none` MUST be shown before the yes, not after.

### 6.2 Consent

Schema: `schemas/consent.schema.json`. Signed by the person's signer, `typ` `oac-consent+jws`.

```json
{"oac":"0.2","type":"consent","iss":"https://atlas.example/signer","sub":"person:7f3a",
 "aud":"https://shop.example/oac","jti":"n_consent_0000000001","iat":1793836780,"exp":1793837080,
 "items":[{"preview":"sha-256:<digest of the preview>","action":"sha-256:<action digest>"}],
 "signer":{"kind":"custodial"}}
```

- One item per Preview, 1 to 20 (a batch: "send these 3 replies?").
- `exp - iat` at most 900.
- `jti` is single-use, at least 16 characters of base64url alphabet.
- `payment` is present if and only if one item pays (section 9).

### 6.3 Verifying a Consent

The executor knows, from its own authentication, the person it acts for (`sub`). If the action's profile names an
`occurrence`, the executor first claims it (5.1: `duplicate_occurrence`, `occurrence_unresolved`). It MUST then run
these checks in this order and report the first failure's code:

1. Envelope (3.3), then the payload's fields (`malformed`).
2. `aud` is this executor: `wrong_audience`. `sub` is the person this executor acts for: `subject_mismatch`.
3. Time: `iat` not more than 60 s in the future (`not_yet_valid`); now before `exp` (`expired`); `exp - iat` within
   900 and positive (`lifetime_too_long`).
4. As many previews and actions as items: `preview_mismatch`.
5. For each item, in order:
   1. the Preview's fields are valid (`malformed`);
   2. `digest(preview)` equals `item.preview`: `preview_mismatch`;
   3. `preview.action` and `digest(action)` both equal `item.action`: `action_mismatch`;
   4. `preview.sub` equals the Consent's `sub`: `subject_mismatch`;
   5. `preview.executor` is this executor: `executor_mismatch`;
   6. now before `preview.exp`: `preview_expired`;
   7. a profile is known for the tool (`unknown_tool`) and is valid (`malformed`);
   8. every argument is declared and valid (section 5 rules 1, 3, 4): `undeclared_argument`, `malformed`;
   9. binding (6.1 rule 1): `binding_mismatch`;
   10. tier is not D: `tier_d`;
   11. for a `pay` effect: section 9 (`payment_missing`, `payment_mismatch`); a second paying item is `malformed`.
6. `payment` present but no item pays: `payment_mismatch`.
7. If the executor requires a device proof: section 3.6.
8. `jti` not seen before: `replay`. Recording the `jti` (until `exp`) and checking it MUST be one atomic step
   (insert-if-absent), so that parallel retries of one Consent run at most once. It happens last, so a refused
   Consent does not use up its nonce.

A valid Consent authorizes exactly the listed actions, once each, at this executor, before `exp`.

## 7. Mandate

### 7.1 Object

Schema: `schemas/mandate.schema.json`. Signed by the person's signer, `typ` `oac-mandate+jws`.

```json
{"oac":"0.2","type":"mandate","id":"md_lunch_1","iss":"https://atlas.example/signer","sub":"person:7f3a",
 "holder":{"type":"agent","id":"lunch-bot"},"goal":"Book and pay for lunch on weekdays, up to $25.",
 "tools":["book_table","pay_order"],
 "bounds":{"calls":{"per_day":5},"amount":{"currency":"USD","per_call_minor":2500,"per_day_minor":5000},
           "payees":["Nobu Boston","Sweetgreen"],"sites":["nobu.example"]},
 "iat":1793833200,"exp":1794438000,"signer":{"kind":"custodial"}}
```

`bounds.calls.per_day` is required. `recipients` entries are an exact address or `@domain`.

### 7.2 What a Mandate can and cannot do

A Mandate stands in for a Consent on tier C. It MUST NOT cover tier D. It MUST NOT be used in a tainted run, and
a run is tainted unless a host the executor trusts says otherwise (section 4): the person is asked instead
(`tainted`). A `pay` tool needs `amount.per_call_minor`, `amount.per_day_minor` and `payees`. A tool that binds `to`
needs `recipients`; no list means nobody.

### 7.3 Checking a Mandate for one action

The executor knows from its own authentication the caller (`holder`) and the person (`sub`), and keeps its own
use counters. In this order:

1. Envelope and fields, as 6.3 step 1.
2. `holder` equals the authenticated caller: `holder_mismatch`. `sub` equals the person: `subject_mismatch`.
3. The id is not revoked and not superseded (7.4), and, when the Mandate names a status entry, its bit is clear
   (7.5): `revoked`; a missing, stale or foreign status list is `status_unknown`.
4. Time, as 6.3 step 3, with a maximum lifetime of 30 days.
5. The action's fields are valid (`malformed`); the tool is in `tools` and is the profile's tool:
   `tool_not_covered`; the profile is valid (`malformed`).
6. Tier is not D: `tier_d`. The run is not tainted: `tainted`.
7. Every argument is declared and valid (section 5): `undeclared_argument`, `malformed`. Usage counters are
   non-negative integers (`malformed`).
8. `pay` without both amount caps and `payees`: `pay_without_caps`.
9. If the tool binds `to`: the Mandate has `recipients` and every address matches one entry, an exact address or
   `@domain` compared with the whole domain, case-insensitively: `recipient_not_allowed`.
10. `payee` in `payees` when the list exists: `payee_not_allowed`. `site` in `sites` when the list exists:
    `site_not_allowed`.
11. If the action carries `amount_minor`: the Mandate has `amount` (`over_amount`), the currency equals
    (`currency_mismatch`), within `per_call_minor` (`over_amount`), and the last 24 hours' total plus this one
    within `per_day_minor` (`over_daily_amount`).
12. Calls in the last 24 hours plus one within `per_day`, and this run's within `per_run`: `over_calls`.

"Day" is a rolling 24-hour window. A run is numbered by the executor (for example inside its integrity-protected
request state), never by the agent, which could otherwise start a new run to reset `per_run`. The executor MUST
count uses atomically with the action (one transaction, or an equivalent lock), so two parallel calls cannot both
pass a limit.

### 7.4 Replacing a Mandate

A Mandate is revoked by its signer; revocation is final. A replacement names the old one in `supersedes`, and the
old one is then revoked. The executor MUST learn revocations from the signer (OAC 0.2 does not fix the format; a
signed status list is expected) and MUST refuse a revoked or superseded id (`revoked`). Without this, narrowing a
Mandate would change nothing: the holder still has the old token.

A replacement **loosens** when, compared with the old one, it has another holder, subject or issuer; a device signer
replaced by a custodial one; a new tool; a later expiry; a higher or removed count or amount cap; another currency;
an amount where there was none; a recipient list where there was none, or a new recipient; a new payee or site, or a
removed payee or site list. The signer MUST NOT sign a loosening replacement without a fresh proof that the person
is present (a new sign-in, a device signature). Narrowing needs no fresh proof. The SDKs' `loosens` function returns
the list of reasons.

### 7.5 Status lists (revocation)

A signer publishes which Mandates it revoked as a signed **status list** (`schemas/status-list.schema.json`, `typ`
`oac-status+jws`), using the bitstring encoding of the W3C Bitstring Status List Recommendation (15 May 2025):
`encoded_list` is `u` + unpadded base64url of the GZIP-compressed bitstring; index 0 is the left-most bit; a set bit
means revoked; at least 16 KB uncompressed (131,072 entries). A Mandate names its entry with
`"status": {"list": <list id>, "index": <n>}`.

Checking (7.3 step 3): the list with that id is present (`status_unknown`), verifies under the signer's keys, is
signed by the Mandate's own `iss` and has the same `id` (`status_unknown`), is fresh (`iat <= now < exp`, and a list
lives at most 7 days: `status_unknown` when stale), decodes as exactly one gzip member with nothing after it and at
most 2 MB uncompressed (`malformed`), and the index is inside it (`malformed`). Then the bit decides (`revoked`).
Revocation is final: a signer MUST NOT clear a bit. A signer SHOULD re-issue lists often (the SDKs default to one
hour) and assign indexes at random so a list does not reveal how many Mandates a person has.

## 8. Receipts and Undo

### 8.1 Receipt

Schema: `schemas/receipt.schema.json`. Signed by the executor, `typ` `oac-receipt+jws`. One per executed action
(including failures), per person, in order:

```json
{"oac":"0.2","type":"receipt","iss":"https://shop.example/oac","sub":"person:7f3a","seq":2,"prev":"sha-256:...",
 "iat":1793836801,"tool":"book_table","tier":"C",
 "authority":{"kind":"consent","ref":"n_consent_0000000001","digest":"sha-256:..."},
 "action":"sha-256:...","preview":"sha-256:...","outcome":"ok","result":"sha-256:...",
 "undo":{"kind":"compensate","until":1793923200}}
```

Rules beyond the schema (`receipt_invalid`):

- tier D never appears;
- `authority.kind` is `consent` (ref = its `jti`), `mandate` (ref = its `id`), `undo` (ref = the Undo request's
  `jti`) or `tier` (MUST NOT carry a ref or a digest; tiers A and B only);
- `consent`, `mandate` and `undo` authorities carry `digest`, the `token_digest` of the exact token the executor
  verified. The executor MUST keep that token with the receipt, so a verifier can later check that it signed what
  the receipt says;
- `undo.kind` `none` carries no `until` or `token`; any other kind on an `ok` outcome carries `until`;
- tier B with outcome `ok` (other than an undo receipt) carries a `native` undo with a `token`;
- a receipt with authority `undo` names the receipt it undoes in `undoes` (its `token_digest`).

`outcome` is `ok`, `failed` or `unknown` (the executor cannot tell whether the action happened; 5.1). When the
tool's profile names an `occurrence`, the receipt carries its value in `occurrence`, and the profile's
`occurrence_scope`, if any, in `occurrence_scope`.

`result` is the digest of the action's result. Receipts SHOULD NOT carry personal data in clear: they carry digests,
and a store holds the details.

### 8.2 Chain

`prev` is `token_digest` of the previous receipt for the same person, and `null` for `seq` 1. Verifying an export
(a contiguous run of receipts, possibly starting after `seq` 1), in order for each receipt: envelope and fields;
rules of 8.1; `iss` is the expected executor (`chain_issuer`); same `sub` throughout (`subject_mismatch`); the first
has `prev` null if and only if its `seq` is 1 (`chain_broken`); each later one has `seq` one more than the one before
(`chain_seq`) and `prev` equal to its `token_digest` (`chain_broken`); no two receipts with outcome `ok` share a scope
(the `occurrence_scope`, else the tool's own scope, as in 5) and an `occurrence` (`duplicate_occurrence`), not counting
undo receipts.

**Seals.** A person's signer MAY countersign the chain from time to time with a **seal**
(`schemas/seal.schema.json`, `typ` `oac-seal+jws`): `{iss, sub, executor, seq, head, iat}`, where `head` is the
`token_digest` of receipt `seq`. When an export is verified with seals, each seal MUST verify under the signer's keys,
name the same person (`subject_mismatch`) and this executor, and name a receipt in the export whose `token_digest`
equals `head` (`seal_mismatch`). A seal therefore exposes any later rewrite of the receipts it covers. A seal and
its receipt MAY also be registered in an IETF SCITT transparency service, so a third party can see that the head
existed at that time; OAC 0.2 does not require it.

### 8.3 Undo request

Schema: `schemas/undo.schema.json`. Signed by the person's signer, `typ` `oac-undo+jws`. `receipt` is the
`token_digest` of the receipt to undo; `mode` is `native` or `compensate`.

A `compensate` undo is a new action (a cancel, a refund) with its own Preview and Consent: its arguments MUST include
`undoes`, the receipt's `token_digest` (declared in the tool's `other_args`), and the request names that Consent's
`jti` in `consent`. The executor verifies that Consent first (6.3), then the request.

The executor checks, in order: envelope and fields; `aud` (`wrong_audience`); time, 900 s maximum lifetime; the named
receipt is the one given (`receipt_mismatch`); that receipt's own envelope, fields and 8.1 rules, under the
executor's keys (their own codes, for example `unknown_key` or `receipt_invalid`); it is this executor's
(`receipt_mismatch`); same `sub` (`subject_mismatch`); its outcome is `ok` and its undo kind is not `none`
(`not_reversible`); `mode` equals the undo kind (`undo_mode_mismatch`); now is not after `undo.until`
(`undo_window_closed`); the receipt was not undone before (`already_undone`; the executor MUST keep the set of
undone receipts); for `compensate`: a consent is named (`malformed`), and the verified Consent has that `jti`, the
same `sub`, and covers an action whose `undoes` is this receipt (`compensation_mismatch`); finally the request's
`jti` is used once, atomically (`replay`).

The executor then undoes, and appends a receipt with authority `undo` and `undoes`. An executor MAY also accept its
own signed-in session for a tier B native undo; the signed request is what makes an undo verifiable by others.

"Undo this run" is a list of undo requests, newest receipt first. Receipts whose kind is `none` MUST be listed to the
person as "cannot be undone", never skipped silently.

## 9. Payments

OAC authorizes a payment; it never carries a credential and never moves money.

1. A `pay` action's Preview MUST bind `amount_minor`, `currency` and `payee`.
2. Its Consent MUST carry `payment`: `rail` (`stripe_link`, `ap2`, `vi`, `other`), `ref` (the rail's own
   authorization: a spend request id, an AP2 mandate id, a Verifiable Intent reference), and `amount_minor`,
   `currency`, `payee` equal to the Preview's fields (`payment_missing`, `payment_mismatch`).
3. The credential (a one-time card, a token) MUST be issued by the rail to the executor, never to the agent or model,
   and MUST NOT be stored. The agent sees at most a handle and the last four digits.
4. The executor SHOULD make the rail enforce the same amount and payee (a second lock that does not depend on the
   executor's own code), and MUST fail closed when they differ.
5. The Receipt carries `payment.rail`, `payment.ref`, and MAY carry `last4` and the merchant's `order` id.
6. A payment Consent cannot be replaced by a Mandate unless the Mandate meets 7.2.
7. A `pay` tool names an `occurrence`, and the executor follows 5.1: a payment whose outcome is unknown is resolved
   with the rail before anyone can pay the same occurrence again.

## 10. Bindings

The MCP binding is in `mcp-extension.md`. Mappings to AP2, Verifiable Intent, ACP, A2A and others are in
`mappings.md`. The dispute evidence profile is in `profiles/dispute.md`.

## 11. Relation to other work

OAC adds three things the protocols around it leave out: a Preview bound into a signed yes, a declared undo kind with
a receipt chain, and one tier vocabulary. It reuses JCS, JWS and JWK thumbprints and does not define identity, rails
or checkout. Where an existing format already covers a part (payment mandates, receipts in transparency logs), OAC
points to it or exports to it (`mappings.md`).

## 12. Security considerations

- **Model-proof by construction.** Nothing a model outputs can mint a Consent or Mandate: the user key is out of its
  reach (section 2), and a model's tier hint can only raise the tier (section 4).
- **What the person saw.** Every argument is either a checked field or an unchanged detail (section 5), so nothing
  runs that was not shown. `summary` is not checkable; clients MUST render `fields` and `details`, escaped. Display
  text cannot carry direction overrides or invisible characters. With `evidence`, a dispute can compare the
  screenshot the person saw with the page that was submitted.
- **Addresses.** One recipient is one bare address; lists, display names and header breaks are refused, and
  `@domain` rules compare the whole domain.
- **Prompt injection.** Taint comes from the host, never the agent; when in doubt a run is tainted, Mandates do not
  apply, and writes rise to tier C (section 4).
- **Replay and races.** Every Consent and Undo request is single-use, audience-bound and short-lived; the nonce is
  recorded atomically and only after every other check passes. Mandate counters are updated atomically with the
  action. A receipt is undone at most once.
- **Who signed.** Keys are bound to one issuer each, and every check names the person the executor acts for, so
  one trusted signer cannot speak for another and one person's permission cannot act for someone else.
- **Revocation.** Executors refuse revoked and superseded Mandates and read signed status lists (7.5); a missing or
  stale list refuses rather than allows. Status lists are short-lived so a revocation takes effect within hours.
- **Time.** Executors need a clock within 60 s of the signer's.
- **Custodial signers** are only as strong as their sign-in, and `signer.kind` is only the signer's word (3.4).
  Require a device proof (3.6) where an independent check matters, for example payments and loosening Mandates.
- **Signatures are not unique.** One payload can have many valid ES256 tokens (3.3). Single use comes from `jti`;
  references name exact token bytes, and those bytes are kept.
- **Retries.** A fresh Consent cannot pay the same order twice: the occurrence record refuses it until the first
  attempt's outcome is known (5.1). This holds only if occurrence ids come from the provider or executor, never the
  agent; an agent that can invent a new id can make a "new" order.
- **Privacy.** Previews and Receipts can reveal what a person does. Store them per person, encrypted, with retention
  limits; share only what a verifier needs (digests prove a match without the content).
- **Profiles are claims.** A tool can lie in its Action Profile (claim `native` and do something irreversible).
  Executors review profiles before trusting them and apply a policy floor to unreviewed tools.
- **One way in.** The checks protect an effect only if nothing reaches that effect without them. A second tool server
  with write access to the same database, a script with the same API key, or an admin console can send the mail or
  move the money with no Preview and no Consent, while every Receipt stays consistent. The defence is to guard the
  keys, not to list the roads: whatever performs an effect needs a credential, and only the executor holds it (13.2).

## 13. Conformance

### 13.1 Implementations

An implementation conforms to OAC 0.2 when it passes every case in `vectors/` (format: `conformance/README.md`),
reporting the same error code as the vector for every refused case. This shows the checks hold when they are used.
It does not show that a deployment uses them on every route to an effect.

### 13.2 Deployments

A deployment that claims OAC protects an effect (an action of tier C) MUST meet three rules:

1. **Name the key.** For each such effect, name the credential that performs it: an OAuth grant and its scope, an API
   key, a database role with write access, a signing key, a payment rail's credential.
2. **Only the executor holds it.** No agent, model, other tool server, script or shared process can use that key.
   Anything else that can reach the effect without it (another database role, an admin account) is a key too: it
   either moves behind the executor, or is listed as a route that only people use, out of any agent's reach.
3. **Pass the bypass check.** Build and verify a Consent for the action, do not present it, then try the effect
   from wherever an agent or tool server runs: through every tool it can call, and directly against the service with
   every credential found there. The effect MUST NOT happen. The check runs again whenever a key, tool server or
   route is added.

The deployment SHOULD publish a coverage statement, one row per effect, for example:

| Effect | Key | Held by | Other routes | Bypass check |
|---|---|---|---|---|
| `send_email` | mail OAuth grant, send scope | executor only | none | refused, 2026-11-06 |
| `pay_order` | rail credential (9.3) | executor only, never stored | provider dashboard (people only) | refused, 2026-11-06 |

A coverage result is one of four, reported as such and never merged into one score: `covered` (complete statement,
check refused every route), `bypass` (an effect happened without the executor), `incomplete` (a key or route is
missing from the statement, or the check skipped one), `not_checked`. Only `covered` supports a claim that OAC
protects the effect. A bypass is a deployment failure, not a failure of the vectors.
