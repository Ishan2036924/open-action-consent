# Conformance

`vectors/*.json` are the test cases every OAC 0.2 implementation must pass. Each file is:

```json
{"oac": "0.2", "about": "...", "cases": [{"name": "...", "op": "verify_consent", "input": {...}, "expect": {"ok": true}}]}
```

`expect` is `{"ok": true}`, `{"error": "<code>"}` (the first failing check, spec section 6.3, 7.3, 8.2, 8.3), or an
op-specific value. Ops:

| op | input | expect |
|---|---|---|
| `jcs` | `value` | `{"canonical": string}` |
| `parse` | `text` (strict JSON) | `{"canonical": string}` |
| `digest` | `value` | `{"digest": string}` |
| `sign` | `key` (label), `alg`, `typ`, `payload` | `{"token": string}`; EdDSA is deterministic, so the token must match byte for byte |
| `tier` | `profile`, `policy_floor`, `tainted`, `hint` | `{"tier": "A".."D"}` |
| `profile` | `profile` | ok / error |
| `binding` | `preview`, `action`, `profile` | ok / error |
| `verify_consent` | `token`, `keys`, `executor`, `sub`, `previews`, `actions`, `profiles`, `now`, `seen_nonces`, `policy_floor`, `tainted`, `device` | ok / error |
| `check_mandate` | `token`, `keys`, `action`, `profile`, `holder`, `sub`, `now`, `tainted`, `usage`, `revoked` | ok / error |
| `loosens` | `old`, `new` (mandate payloads) | `{"reasons": [sorted]}` |
| `verify_chain` | `tokens`, `keys`, `executor`, `sub` | ok / error |
| `check_undo` | `token`, `keys`, `executor`, `receipt_token`, `receipt_keys`, `now`, `seen_nonces`, `undone`, `compensation` | ok / error |
| `claim_occurrence` | `state` (`null`, `running`, `failed`, `unknown` or `ok`: the last attempt's state) | ok / error |
| `status_bit` | `encoded_list`, `index` | `{"revoked": bool}` |
| `metadata_url` | `iss` | `{"url": string}` |
| `keyset_from` | `docs` ([[iss, metadata], ...]), `kid` | `{"issuer": string}` |

`check_mandate` also takes `status_lists` ({list id: token}); `verify_chain` takes `seals` and `seal_keys`.
`verify_consent`'s optional `device` is `{"proof": <device proof or null>, "credentials": {id: JWK}, "rp_id", "origins", "device_bound"?}`
(spec 3.6); when present, the executor requires a device proof.
`keys` are grouped by issuer: `{"<iss>": [<public JWK>, ...]}`. Vector files are read with the strict parser.

Test keys: `key` labels map to `sha-256("oac-v0.1 test key: " + label)` as the Ed25519 seed (ES256: that value
mod (n - 1) + 1). They are public on purpose; never use them for anything real.

Run:

```
PYTHONPATH=sdk/python/src python -m oac.conformance vectors      # Python
node sdk/typescript/src/conformance.ts vectors                     # TypeScript (Node 23.6+)
```

Regenerate after a spec change with `python tools/make_vectors.py`. Its expected results are written by hand from
the spec; the script stops if the Python SDK disagrees.
