# OAC for the official MCP TypeScript SDK v2

Install: `npm install open-action-consent @modelcontextprotocol/server`.

Adds Open Action Consent to an `McpServer` from `@modelcontextprotocol/server` 2.4+. The v2 SDK has no tool-call
interceptor, so OAC wraps each tool you register through it.

```ts
import * as z from "zod";
import { McpServer } from "@modelcontextprotocol/server";
import { OAC, ID } from "open-action-consent/mcp";

const oac = new OAC({ executor: "https://tables.example/oac", key: executorKey, signers: signerKeys,
  consentUrl: (p) => `https://signer.example/consent?r=${p.id}`, person: (ctx) => userIdFromYourAuth(ctx),
  tainted: (ctx) => yourHostSaysOutsideTextEntered(ctx) });
const server = new McpServer({ name: "tables", version: "1.0.0" }, { capabilities: { tools: {}, extensions: { [ID]: oac.settings() } } });

oac.registerTool(server, "book_table",
  { description: "Book a table", inputSchema: z.object({ restaurant: z.string(), time: z.string(), party: z.number() }) },
  { effect: "write", undo: "compensate", windowS: 86400, binds: { payee: "restaurant", when: "time", count: "party" } },
  async ({ restaurant, time, party }) => ({ content: [{ type: "text", text: "Booked." }] }));
```

Behaviour matches the [Python plug-in](mcp-python.md): tier A/B run (B with a receipt and undo token in
`_meta["com.atlasiw/oac-receipt"]`); tier C answers `input_required` with a URL-mode elicitation and runs only with
a valid signed Consent; tier D, unprofiled tools and undeclared arguments never run. Passkeys work the same way:
`device: (person, action) => check | null` in the options, `oac.acceptConsent(token, proof)` from the signer page,
and `oac.deviceProofs` keeps them. A profile's `occurrenceScope` shares order ids across tools.

Differences from the Python SDK, handled here:

| v2 SDK behaviour | What the plug-in does |
|---|---|
| does not integrity-protect `requestState` | OAC signs its own (HMAC-SHA256, 15-minute expiry, bound to the person and the action digest) |
| turns errors thrown in a tool into tool results | a client without the extension or URL elicitation gets a tool error that names `-32021`; nothing runs |

Tests: `sdk/typescript/test/mcp.test.ts` (end to end through the SDK's `InMemoryTransport` and `Client`). Stores are in memory for now.
