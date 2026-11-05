# Dispute Evidence Pack (OAC profile, informative)

When an agent's action goes wrong, the person (or their card issuer) needs to show what was authorized and what
happened. OAC objects already hold that; this profile says how to bundle them. It defines no new signatures.

## Bundle

A JSON object, `"type": "dispute-pack"`:

| Field | Holds |
|---|---|
| `oac`, `type` | `"0.2"`, `"dispute-pack"` |
| `sub` | the person |
| `claim` | `{"kind": "not_authorized" \| "not_as_described" \| "not_received" \| "not_cancelled", "receipt": <token_digest>}` |
| `mandate` | the Mandate token, if one was used |
| `previews` | the Preview objects the Consent covers |
| `consent` | the exact Consent token the executor kept (or `null` when a Mandate was the authority) |
| `device_proof` | the device proof for that Consent, if the executor required one (spec 3.6) |
| `receipts` | the chain segment from the disputed receipt back to the last seal, plus any undo receipts |
| `keys` | the public JWKs of the signer and the executor |
| `attachments` | files whose digests appear in the Preview `evidence` (screenshot, page) and the merchant's policy page |

Anyone can verify the pack offline with the SDKs: the Consent against the Previews, its `token_digest` against the
receipt's `authority.digest`, the device proof against the Consent, the receipts as a chain, and each attachment
against its digest.

## What each claim needs

| Claim | Shown by | Commonly filed under (check the network's current rules) |
|---|---|---|
| `not_authorized`: the agent bought something the person never approved | no Consent covers the receipt's `action` digest, or the Mandate's bounds exclude it (re-run spec 7.3) | Visa 10.4, Mastercard 4837 |
| `not_as_described`: what arrived differs from what was approved | the Preview `fields` and `evidence` vs the merchant's delivery | Visa 13.3, Mastercard 4853 |
| `not_received` | the receipt (order id, `iat`) and no delivery proof | Visa 13.1, Mastercard 4855 |
| `not_cancelled`: the person cancelled in the free window | the undo request and undo receipt inside `undo.until`, and the Preview's `cancel_policy` | depends on the merchant's terms |

## What it cannot prove

- That the person read the Preview. It proves their signer signed this exact Preview.
- That `summary` matched `fields`. Only `fields` are checked; that is why clients must render them.
- What a merchant's system did after the executor's call, beyond what the merchant returned.
- Anything about a payment rail's own records; the pack points to them (`payment.ref`).

Card networks set evidence rules, not OAC. This pack is a convenient, verifiable bundle, not a guarantee of outcome.
