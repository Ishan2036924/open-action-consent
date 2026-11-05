# open-action-consent (JavaScript / TypeScript)

**A verifiable "yes" for things AI agents do for people.** Preview → signed Consent → the action runs only if it
checks out → signed Receipt with Undo. Zero runtime dependencies for the core.
Spec and source: <https://github.com/Ishan2036924/open-action-consent>

## Everything in this one package

| Part | Import | Also install | Guide |
|---|---|---|---|
| Core: previews, consents, mandates, receipts, undo, status lists, key discovery, `Gate` | `open-action-consent` | nothing | [README](https://github.com/Ishan2036924/open-action-consent#readme) |
| MCP servers (official MCP TypeScript SDK v2) | `open-action-consent/mcp` | `@modelcontextprotocol/server` | [guide](https://github.com/Ishan2036924/open-action-consent/blob/main/guides/mcp-typescript.md) |
| Vercel AI SDK 7 | `open-action-consent/vercel-ai` | `ai` | [guide](https://github.com/Ishan2036924/open-action-consent/blob/main/guides/vercel-ai.md) |

```
npm install open-action-consent
```

```ts
import { Gate, buildPreview, makeConsent, verifyConsent, KeySet } from "open-action-consent";
```

Needs Node 22.14+ (or a modern bundler). Python, the Gated Browser and the approval page: `pip install
open-action-consent`. License: Apache-2.0 (code), CC BY 4.0 (spec text).
