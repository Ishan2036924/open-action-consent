# OAC for the official MCP Python SDK

`pip install "open-action-consent[mcp]"`, then `from oac.mcp import OACExtension`.

Adds Open Action Consent to any `MCPServer` (`mcp` 2.3+, protocol 2026-07-28), as the MCP extension
`com.atlasiw/oac` (spec: [../spec/mcp-extension.md](../spec/mcp-extension.md)).

```python
from mcp.server.mcpserver import MCPServer
from oac.mcp import OACExtension

oac = OACExtension(executor="https://tables.example/oac", key=executor_key, signers=signer_keys,
                   consent_url=lambda preview: f"https://signer.example/consent?r={preview['id']}",
                   person=lambda ctx: user_id_from_your_auth(ctx),
                   tainted=lambda ctx: your_host_says_outside_text_entered(ctx))
server = MCPServer("tables", extensions=[oac])

@server.tool(meta=oac.profile("book_table", effect="write", undo="compensate", window_s=86400,
                              binds={"payee": "restaurant", "when": "time", "count": "party"}))
async def book_table(restaurant: str, time: str, party: int) -> str:
    ...
```

What happens on each call:

| Tier | Example | What the extension does |
|---|---|---|
| A | read | runs |
| B | `undo="native"` write | runs, returns a signed receipt with an undo token in `_meta["com.atlasiw/oac-receipt"]` |
| C | send, pay, compensate/none write, or any write in a tainted run | answers `input_required` with a URL-mode elicitation to your signer page; runs only after a valid signed Consent for that exact preview, then returns the receipt |
| D | `tier_floor="D"` | never runs |
| — | a tool with no profile, or an argument the profile does not declare | never runs |

Your signer page calls `oac.preview(id)` to show the preview and `oac.accept_consent(token)` to hand over the
signed Consent (it is verified on arrival and never replaced). A client that does not declare the extension or URL
elicitation gets `-32021`. The SDK seals `requestState` itself, so a retry with changed arguments is refused even
before OAC's own check.

**Passkeys.** To require a passkey for some actions, pass `device=lambda person, action: DeviceCheck(None,
credentials, rp_id, origins)` (or `None` when no passkey is needed). The signer page posts the proof with the token,
`oac.accept_consent(token, proof=proof)`, or the client sends it in `_meta["com.atlasiw/oac-device-proof"]`. Without a
valid proof nothing runs (spec 3.6). `oac.device_proofs` keeps each proof by the token's digest, next to `oac.tokens`.

**Orders across tools.** Two pay tools that use one provider account pass the same `occurrence_scope` to
`oac.profile(...)`, so an order paid through one cannot be paid again through the other (spec 5.1). Once a tool has
orders, registering it again with another scope, or without its occurrence, raises `ValueError`; move the
records in your store first.

Tests: `sdk/python/tests/integrations/mcp` (end to end through the SDK's in-memory client). Stores are in memory for now;
production servers keep previews, consents, nonces (atomic) and receipts in their own database.
