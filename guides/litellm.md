# OAC for the LiteLLM MCP gateway

Install: `pip install "open-action-consent[litellm]"`. Tested with LiteLLM 1.108.x; another version logs a warning at
start.

The [LiteLLM proxy](https://docs.litellm.ai/docs/mcp) can sit in front of MCP servers and run guardrails before each
tool call. `oac.litellm.OACGuardrail` uses that hook to gate every tool call that passes through, for MCP servers that
know nothing about OAC: tiers, the person's signed Consent for tier C, and hash-chained receipts. The MCP servers stay
as they are.

```yaml
# config.yaml
mcp_servers:
  mail:
    url: https://mail-tools.internal/mcp
guardrails:
  - guardrail_name: oac
    litellm_params:
      guardrail: oac.litellm.OACGuardrail
      mode: [pre_mcp_call]
      default_on: true
      executor: https://gateway.example/oac      # this gateway's OAC identity (the Consent's audience)
      key_file: /etc/oac/executor.pem            # Ed25519 private key that signs receipts
      signers_file: /etc/oac/signers.json        # {"https://signer.example": [public JWK, ...]}
      profiles_file: /etc/oac/profiles.json      # one Action Profile per server/tool
      # optional:
      receipts_dir: /var/lib/oac/receipts        # one append-only chain per person
      consent_url: https://approve.example/consent?preview={id}
      consent_port: 8790                         # intake endpoint for signed Consents (binds 127.0.0.1)
      tainted: true                              # can outside text reach the agents? unknown means yes
      person_from: user_id                       # or team_id: whose action it is, from LiteLLM's key check
```

```bash
openssl genpkey -algorithm ed25519 -out /etc/oac/executor.pem && chmod 600 /etc/oac/executor.pem
```

`profiles.json` names each tool as `server/tool`, so the same tool name on two servers never shares a tier:

```json
{
  "mail/read_inbox": {"effect": "read", "binds": {"title": "query"}},
  "mail/send_email": {"effect": "send", "binds": {"to": "to", "title": "subject"}, "other_args": ["body"]},
  "tasks/add_task": {"effect": "write", "undo": "native", "window_s": 600, "binds": {"title": "title"}}
}
```

## One tool call

| Case | What happens |
|---|---|
| No profile for `server/tool`, or arguments the profile does not declare | refused (HTTP 403, `oac_refused`), nothing runs |
| Tier A or B | runs; the outcome closes it with a signed receipt |
| Tier C, no Consent yet | refused with `oac_consent_required`, the Preview, and `consent_url` for it; nothing runs |
| Tier C, the person's Consent for exactly these arguments is held | verified (signature, person, Preview digest, action, expiry, one-time use, occurrence) and runs |
| Tier D | refused |
| The calling key has no `user_id` (or `team_id`) | refused: an action with no person is never run |

The arguments checked are the ones that will run: if an earlier guardrail rewrote them, the rewrite is what gets
approved, and OAC pins them so nothing after it can change them. OAC refuses every call while another `pre_mcp_call`
guardrail is registered after it, so list it last.

The person comes from the key LiteLLM authenticated for the call (the `user_api_key_dict` it hands the hook: its
`user_id` by default, or `team_id`), never from the request: a person named in the request body or its metadata is
ignored, and a key without one is refused. Arguments never carry authority: a model that writes "approved" into
them, or pastes a real Consent into a text field, gets a refusal or a new Preview.

## Getting the Consent to the gateway

The refusal goes back to the MCP client, usually as a tool error the model reads ("Needs the person's approval: ...
Approve, then call again."). The person approves the Preview in their signer (for example the OAC approval page,
`oac.approver`), and the signed Consent reaches the gateway in one of three ways:

1. **Intake endpoint** (`consent_port`): `POST /oac/consents` with `{"consent": "<token>"}`; `GET /oac/previews/<id>`
   returns the Preview to show. A Consent is self-authenticating, so the endpoint needs no login, but it binds to
   127.0.0.1 by default: put it behind your own access rules before opening it wider.
2. **Header**: the host app retries the same call with `x-oac-consent: <token>`.
3. **In code**: `guardrail.accept_consent(token)` from your own approval flow.

The retried call then runs once. A second retry needs a new Consent.

## Outcomes and receipts

| What LiteLLM reports | Receipt outcome |
|---|---|
| The tool returned a result | `ok` |
| A refusal after OAC (rate limit, permission check) before the tool ran | `failed` (it did not happen) |
| The tool returned an error, or the call broke | `unknown` when the profile tracks occurrences (it may have happened), else `failed` |
| No outcome within `ticket_timeout_s` (900 s; the client hung up, the worker stopped) | as above, closed on the next call |

An `unknown` occurrence cannot run again until `guardrail.gate.resolve(...)` records what the provider says happened.
Receipts live in `guardrail.gate.receipts` and, with `receipts_dir`, in one file per person (named by a hash, not by
the person), and continue the same chain after a restart. Check them with `verify_chain` and `verify_export`.

## Known limits

- **Deployment rules still apply** (spec 13.2): name the credential each tier C tool uses, make sure only the MCP
  server behind this gateway holds it, and run the bypass check. A gateway cannot stop an agent that holds the mail
  key itself.
- **Stores live in memory** (nonces, occurrences, pending Previews). A restart forgets used Consents until they expire,
  and several LiteLLM workers do not share them; run one worker, or pass a `Gate` with database-backed stores
  (`OACGuardrail(gate=...)`).
- **Block and retry, not MCP elicitation.** LiteLLM 1.108 has no guardrail-level way to send a URL elicitation, so
  tier C is a refusal plus a retry. MCP servers that use input-required rounds run the hook again for each round, so
  tier C tools on such servers need a Consent per round.
- **Passkeys**: device proofs are accepted on the intake endpoint (`device_proof`) and by `accept_consent`; checking
  them needs a `Gate` built with a `device` callback.
